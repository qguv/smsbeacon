#!/usr/bin/env python3

from flask import Flask, request, make_response, g, Blueprint
import plivo_mock as plivo

from enum import Enum
from time import sleep
from threading import Thread
import pymysql
import os

import settings
import responses
import commands

bp = Blueprint(settings.appname, __name__)
app = Flask(__name__)

p = plivo.RestAPI(settings.plivo_id, settings.plivo_token)

def get_db():
    if not hasattr(g, 'db'):
        g.db = pymysql.connect(
                host=settings.db_host,
                port=settings.db_port,
                user=settings.db_user,
                password=settings.db_password,
                db=settings.db_database,
                charset='utf8mb4')
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

@app.cli.command('initdb')
def init_db():
    db = get_db()
    with db.cursor() as c:
        for instance, d in settings.db_init.items():

            c.execute("insert into instances (instance, name, community, alias) values (%s, %s, %s, %s)",
                    [instance, d.get("name", "beacon"), d["community"], d.get("alias", None)])

            for phone in d.get("subscribers", []):
                c.execute("insert into subscribers (instance, phone) values (%s, %s)", [instance, phone])

            for phone, name in d.get("investigators", {}).items():
                c.execute("insert into investigators (instance, phone, name) values (%s, %s, %s)", [instance, phone, name])

            for phone in d.get("banned", []):
                c.execute("insert into banned (instance, phone) values (%s, %s)", [instance, phone])

    db.commit()
    print('Initialized the database.')

def get_subscribers(instance) -> [str]:
    c = get_db().cursor()
    c.execute("select phone from subscribers where instance = %s", [instance])
    try:
        return [ x[0] for x in c.fetchall() ]
    except:
        return []

def get_investigators(instance) -> {"phone": "name"}:
    c = get_db().cursor()
    c.execute("select phone, name from investigators where instance = %s", [instance])
    try:
        return { phone: name for phone, name in c.fetchall() }
    except:
        return {}

def get_banned(instance) -> [str]:
    c = get_db().cursor()
    c.execute("select phone from banned where instance = %s", [instance])
    try:
        return [ x[0] for x in c.fetchall() ]
    except:
        return []

def get_queue(instance) -> [int]:
    c = get_db().cursor()
    c.execute("select q.id from queue q inner join instances i on q.dst = i.instance or q.dst = i.alias where i.instance = %s", [instance])
    try:
        return [ x[0] for x in c.fetchall() ]
    except:
        return []

def get_instance(instance_or_alias) -> ("name", "instance") or UninitializedNumber:
    c = get_db().cursor()
    c.execute("select name, instance from instances where alias = %s or instance = %s", [instance_or_alias, instance_or_alias])
    try:
        name, instance = c.fetchone()
        if instance is None:
            instance = instance_or_alias
        return (name, instance)
    except:
        raise UninitializedNumber

def print_msg(msg):
    print("Reported by: {}\nUsing number: {}\nMessage: {}".format(msg["src"], msg["dst"], msg["text"]))

def blast(msg, wallops=False):
    instance_or_alias = msg["dst"]

    try:
        name, instance = get_instance(instance_or_alias)
    except UninitializedNumber:
        print("Not blasting message because the number isn't set up.")
        return

    # send to subscribers unless it's a message to the investigators
    dest = [] if wallops else get_subscribers(instance)

    # Investigators get messages as they enter the queue, so they don't need
    # them as they leave the queue. But if the message bypassed the queue (i.e.
    # is from an investigator or is a wallops message to investigators),
    # investigators need a copy too.
    investigators = get_investigators(instance)
    from_investigator = msg["src"] in investigators
    if from_investigator or wallops:
        dest.extend(investigators.keys())

    # don't send it back to the reporter
    try:
        dest.remove(msg["src"])
    except ValueError:
        pass

    if wallops:
        print("\nSending message to all investigators:")
    elif from_investigator:
        print("\nBlasting report to subscribers and investigators:")
    else:
        print("\nBlasting report to subscribers, and informing reporter and investigators:")
    print_msg(msg)

    # if wallops, say so and from whom
    wallops_msg = "(to investigators from {}) ".format(investigators.get(msg["src"], msg["src"])) if wallops else ""

    # send out the report
    p.send_message({"src": instance,
                    "dst": "<".join(dest),
                    "text": "{}: {}{}".format(name, wallops_msg, msg["text"])})

    # if it's a wallops, we've already informed everyone appropriately
    if not wallops:

        # notify the reporter that we've sent the report
        p.send_message({"src": msg["dst"],
                        "dst": msg["src"],
                        "text": "{}: we've sent out your report, thank you!".format(name)})

        # don't send it back to the reporter
        dest = list(investigators.keys())
        try:
            dest.remove(msg["src"])
        except ValueError:
            pass

        # notify investigators that we've sent the report
        p.send_message({"src": instance,
                        "dst": "<".join(dest),
                        "text": "{}: message from {} sent to subscribers".format(name, msg["src"])})

def enqueue(msg) -> int:
    db = get_db()
    c = db.cursor()
    c.execute("insert into queue (src, dst, text, delay) values (%s, %s, %s, %s)",
            [msg["src"], msg["dst"], msg["text"], settings.veto_delay])
    db.commit()

    print("\nEnqueued report {}:".format(c.lastrowid))
    print_msg(msg)

    return c.lastrowid

def dequeue(msgid) -> bool:
    db = get_db()
    c = db.cursor()
    c.execute("delete from queue where id = %s", [msgid])
    db.commit()

    db_changed = bool(c.rowcount)
    if db_changed:
        print("\nRemoved report {} from the queue.".format(msgid))
    return db_changed

def send_immediately(msgid, msg) -> bool:
    print("\nReport {} explicitly approved for sending.".format(msgid))
    blast(msg)
    return dequeue(msgid)

def queue_runner():
    while True:
        sleep(settings.queue_interval)

        # each queue sweep is handled in a new app context
        with app.app_context():
            db = get_db()
            c = get_db().cursor()

            c.execute("update queue set delay = delay - 1")

            c.execute("select src, dst, text from queue where delay <= 0")
            to_blast = c.fetchall()

            c.execute("delete from queue where delay <= 0")
            db.commit()

            for msg in to_blast:
                print("\nMessage {} passed through investigation period with no comments, so it's been automatically approved.".format(msg["id"]))
                blast({"src": msg[0],
                       "dst": msg[1],
                       "text": msg[2]})

def subscribe(instance: str, phone: str):
    db = get_db()
    with db.cursor() as c:
        c.execute("insert into subscribers (instance, phone) values (%s, %s)", [instance, phone])
    db.commit()
    print("\nSubscribed {} to {}.".format(phone, instance))

def unsubscribe(instance: str, phone: str) -> bool:
    '''returns whether the number was subscribed in the first place'''

    db = get_db()
    with db.cursor() as c:
        c.execute("delete from subscribers where instance = %s and phone = %s", [instance, phone])
        db_changed = bool(c.rowcount)
    db.commit()

    if db_changed:
        print("\nUnsubscribed {}.".format(number))

    return db_changed

def ban(instance: str, phone: str):
    db = get_db()
    with db.cursor() as c:
        c.execute("delete from subscribers where phone = %s", [phone])
        c.execute("insert into banned (instance, phone) values (%s, %s)", [instance, phone])
    db.commit()
    print("\nBanned {}.".format(number))

class UserType(Enum):
    BANNED = -1
    UNSUBSCRIBED = 0
    SUBSCRIBED = 1
    INVESTIGATOR = 1337

    @classmethod
    def from_number(cls, number, subscribers, banned, investigators):
        if number in investigators:
            return cls.INVESTIGATOR
        elif number in banned:
            return cls.BANNED
        elif number in subscribers:
            return cls.SUBSCRIBED
        else:
            return cls.UNSUBSCRIBED

class InvalidNumber(ValueError):
    pass

class UninitializedNumber(KeyError):
    pass

def sanitize_number(number: str):
    '''defend against possible SQL or plivo-XML injection attacks which rely on
    non-numeric characters in To and From numbers'''
    if not all(ord('0') <= ord(digit) <= ord('9') for digit in number):
        raise InvalidNumber
    return number

@bp.route('/test/', methods=['GET'])
@app.route('/test/', methods=['GET'])
def test():
    return "OK"

@bp.route('/', methods=['GET', 'POST'])
def receive_sms():
    try:
        msg = {"src": sanitize_number(request.values.get('From', None)),
               "dst": sanitize_number(request.values.get('To', None)),
               "text": request.values.get('Text', None)}
        name, instance = get_instance(msg["dst"])

    except InvalidNumber:
        return make_response("invalid number", 406)
    except UninitializedNumber:
        return make_response("uninitialized number", 406)

    if not (msg["src"] and msg["dst"] and msg["text"]):
        return make_response("missing parameter", 406)

    msg["text"] = msg["text"].strip()

    if not msg["text"]:
        print("\nIgnoring empty text")
        return make_response("empty", 406)

    db = get_db()
    c = db.cursor()

    subscribers = get_subscribers(instance)
    banned = get_banned(instance)
    investigators = get_investigators(instance)

    user_type = UserType.from_number(msg["src"],
            subscribers=subscribers,
            banned=banned,
            investigators=investigators)

    alias_msg = "" if msg["dst"] == instance else " (alias for {})".format(instance)

    print("\nReceived SMS from {} ({}) to {}{}: {}".format(msg["src"], user_type.name.lower(), msg["dst"], alias_msg, msg["text"]))

    if user_type is UserType.BANNED:
        if settings.shadowbans:
            print("\nResponding to banned user {}".format(msg["src"]))
            return responses.queued(name, msg["src"], msg["dst"])
        else:
            print("\nIgnoring banned user {}".format(msg["src"]))
            return make_response("", 201)

    if msg["text"].lower() == "unstop":
        if user_type is UserType.UNSUBSCRIBED:
            subscribe(instance, msg["src"])
            return responses.subscribed(name, msg["src"], msg["dst"])
        return responses.already_subscribed(name, msg["src"], msg["dst"])

    if msg["text"].lower() in commands.unsubscribe:
        if user_type is UserType.UNSUBSCRIBED:
            return responses.not_subscribed(name, msg["src"], msg["dst"])
        unsubscribe(instance, msg["src"])
        return responses.unsubscribed(name, msg["src"], msg["dst"])

    if user_type is not UserType.UNSUBSCRIBED and msg["text"].lower() in commands.subscribe:
        return responses.already_subscribed(name, msg["src"], msg["dst"])

    if user_type is UserType.UNSUBSCRIBED and commands.has_subscribe_phrase(msg["text"]):
        subscribe(instance, msg["src"])
        return responses.subscribed(name, msg["src"], msg["dst"])

    if user_type is not UserType.INVESTIGATOR:
        msgid = enqueue(msg)

        print("\nInforming investigators of report {}:".format(msgid))
        print_msg(msg)

        p.send_message({"src": instance,
                        "dst": "<".join(investigators.keys()),
                        "text": '{}: new report "{}"'.format(name, msg["text"])})

        p.send_message({"src": instance,
                        "dst": "<".join(investigators.keys()),
                        "text": '{}: Can you check this out? Respond with either yes {} or no {}. You can also: approve {}, veto {}, or ban {}'.format(
                            name, msgid, msgid, msgid, msgid, msgid)})

        return responses.queued(name, msg["src"], msg["dst"])

    # INVESTIGATOR COMMANDS BELOW

    cmd = msg["text"].strip('"').split()
    try:
        if cmd[0].lower() in ("yes", "no", "approve", "veto", "ban"):

            # get message details iff it is in our instance
            c.execute("select src, dst, text from queue q inner join instances i on q.dst = i.instance or q.dst = i.alias where i.instance = %s and q.id = %s",
                [instance, cmd[1]])

            try:
                q_src, q_dst, q_text = c.fetchone()
            except:
                return responses.nomsg(name, cmd[1], msg["src"], msg["dst"])

            msg_requested = {"src": q_src,
                             "dst": q_dst,
                             "text": q_text}

            if cmd[0].lower() == "approve":
                if send_immediately(cmd[1], msg_requested):
                    return responses.approved(name, cmd[1], msg["src"], instance, investigators)
                return responses.nomsg(name, cmd[1], msg["src"], msg["dst"])

            if cmd[0].lower() == "yes":
                c.execute("update queue set delay = %s where id = %s", [settings.investigate_delay, cmd[1]])

                # tell other investigators the name of the investigator looking into it
                dest = list(investigators.keys())
                try:
                    dest.remove(msg["src"])
                except:
                    pass

                p.send_message({"src": instance,
                                "dst": "<".join(dest),
                                "text": "{}: {} is looking into message {}".format(name, investigators.get(msg["src"], msg["src"]), cmd[1])})

                return responses.good_luck(name, cmd[1], msg["src"], msg["dst"])

            if cmd[0].lower() == "no":
                return responses.ack_cant_go(name, msg["src"], msg["dst"])

            # it's a veto or ban: dequeue the message
            if dequeue(cmd[1]):
                if cmd[0].lower() == "ban":
                    ban(instance, msg_requested["src"])
                    return responses.ban(name, cmd[1], msg_requested["src"], msg["src"], msg["dst"], investigators)
                return responses.vetoed(name, cmd[1], msg["src"], msg["dst"], investigators)

            return responses.nomsg(name, cmd[1], msg["src"], msg["dst"])

        if msg["text"].lower() in ("subscribers", "subscribed", "signups", "sign-ups", "signed up", "signed-up", "users"):
            return responses.subscribers(name, msg["src"], len(get_subscribers(instance)) + len(investigators), msg["dst"])

        if msg["text"].lower() == "investigators":
            return responses.investigators(name, msg["src"], msg["dst"], investigators)

        if cmd[0].lower() == "investigators":
            msg["text"] = " ".join(cmd[1:])
            blast(msg, wallops=True)
            return responses.wallops_ok(name, msg["src"], msg["dst"])

        if msg["text"].lower() == "queue":
            return responses.queue_status(name, msg["src"], get_queue(instance), msg["dst"])

        if msg["text"].lower() in ("banned", "bans"):
            return responses.banned(name, msg["src"], len(get_banned(instance)), msg["dst"])

        if msg["text"].lower() == "ping":
            return responses.pong(name, msg["src"], msg["dst"])

    except IndexError:
        return responses.nomsgid(name, msg["src"], msg["dst"])

    # direct blast message
    blast(msg)
    return make_response("", 201)

app.register_blueprint(bp, url_prefix="/" + settings.root_key)

if __name__ == "__main__":
    t = Thread(target=queue_runner)
    t.start()
    app.run(host='0.0.0.0', port=settings.port)
