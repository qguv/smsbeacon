#!/usr/bin/env python3

from flask import Flask, request, make_response, g, Blueprint
import plivo

from enum import Enum
from time import sleep
from threading import Thread
import sqlite3
import os

import settings
import responses
import commands

bp = Blueprint(settings.appname, __name__)
app = Flask(__name__)

p = plivo.RestAPI(settings.plivo_id, settings.plivo_token)

def connect_db():
    rv = sqlite3.connect(os.path.join(app.root_path, settings.db_filename))
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    if not hasattr(g, 'db'):
        g.db = connect_db()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    for number in settings.initial_subscribers:
        db.execute("insert into subscribers (number) values (?)", [number])
    for number in settings.initial_banned:
        db.execute("insert into banned (number) values (?)", [number])
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    init_db()
    print('Initialized the database.')

def get_subscribers() -> [str]:
    return [ x["number"] for x in get_db().execute("select number from subscribers").fetchall() ]

def get_banned() -> [str]:
    return [ x["number"] for x in get_db().execute("select number from banned").fetchall() ]

def get_queue() -> [int]:
    return [ x["id"] for x in get_db().execute("select id from queue").fetchall() ]

def print_msg(msg):
    print("Reported by: {}\nUsing number: {}\nMessage: {}".format(msg["src"], msg["dst"], msg["text"]))

def blast(msg, from_vetoer=False):
    dest = get_subscribers()

    # if from a vetoer, treat other vetoers like subscribers
    if from_vetoer:
        dest.extend(settings.vetoers.keys())

    try:
        dest.remove(msg["src"])
    except ValueError:
        pass

    if from_vetoer:
        print("\nBlasting report to subscribers and vetoers and informing the vetoer who submitted it!")
    else:
        print("\nBlasting report to subscribers, and informing reporter and vetoers!")
    print_msg(msg)

    # send the report to subscribers
    p.send_message({"src": msg["dst"],
                    "dst": "<".join(dest),
                    "text": "{}: {}".format(settings.appname, msg["text"])})

    # notify vetoers that we've sent the report
    if not from_vetoer:
        p.send_message({"src": msg["dst"],
                        "dst": "<".join(settings.vetoers.keys()),
                        "text": "{}: message from {} sent to subscribers".format(settings.appname, msg["src"])})

    # notify the reporter that we've sent the report
    # don't do this for vetoers; we send that in the HTTP Response
    if not from_vetoer:
        p.send_message({"src": msg["dst"],
                        "dst": msg["src"],
                        "text": "{}: we've sent out your report, thank you!".format(settings.appname)})

def wallops(text, by, number):
    dest = list(settings.vetoers.keys())
    try:
        dest.remove(by)
    except ValueError:
        pass
    p.send_message({"src": number,
                    "dst": "<".join(dest),
                    "text": '{}: message to vetoers from {} (not sent to subscribers): "{}"'.format(
                        settings.appname,
                        settings.vetoers[by],
                        text)})

def inform(msgid, msg: str):
    print("\nInforming vetoers of report {}.".format(msgid))
    print_msg(msg)

    p.send_message({"src": msg["dst"],
                    "dst": "<".join(settings.vetoers.keys()),
                    "text": '{}: ok/veto/ban {}? "{}"'.format(settings.appname, msgid, msg["text"])})

def enqueue(msg) -> int:
    db = get_db()
    c = db.execute("insert into queue (src, dst, text, delay) values (?, ?, ?, ?)",
            [msg["src"], msg["dst"], msg["text"], settings.veto_delay])
    db.commit()

    print("\nEnqueued report {}.".format(c.lastrowid))
    print_msg(msg)

    return c.lastrowid

def dequeue(msgid) -> bool:
    db = get_db()
    c = db.execute("delete from queue where id = ?", [msgid])
    db.commit()

    db_changed = bool(c.rowcount)
    if db_changed:
        print("\nRemoved report {} from the queue.".format(msgid))
        return True

    return False

def send_immediately(msgid) -> bool:
    msg = get_db().execute("select src, dst, text from queue where id = ?", [msgid]).fetchone()
    if msg is None:
        return False

    print("\nReport {} explicitly approved for sending.".format(msgid))
    blast(msg)
    return dequeue(msgid)

def queue_runner():
    while True:
        sleep(settings.queue_interval)

        # each queue sweep is handled in a new app context
        with app.app_context():
            db = get_db()

            db.execute("update queue set delay = delay - 1")
            to_blast = db.execute("select id, src, dst, text from queue where delay <= 0").fetchall()
            db.execute("delete from queue where delay <= 0")
            db.commit()

            for msg in to_blast:
                print("\nMessage {} passed through veto period with no comments, so it's been automatically approved.".format(msg["id"]))
                blast(msg)

def subscribe(number: str):
    db = get_db()
    db.execute("insert into subscribers (number) values (?)", [number])
    db.commit()
    print("\nSubscribed {}.".format(number))

def unsubscribe(number: str) -> bool:
    '''returns whether the number was subscribed in the first place'''

    db = get_db()
    c = db.execute("delete from subscribers where number = ?", [number])
    db_changed = bool(c.rowcount)
    db.commit()

    if db_changed:
        print("\nUnsubscribed {}.".format(number))

    return db_changed

def ban(number):
    db = get_db()
    db.execute("delete from subscribers where number = ?", [number])
    db.execute("insert into banned (number) values (?)", [number])
    db.commit()
    print("\nBanned {}.".format(number))

class UserType(Enum):
    BANNED = -1
    UNSUBSCRIBED = 0
    SUBSCRIBED = 1
    VETOER = 1337

    @classmethod
    def from_number(cls, number, subscribers, banned, vetoers):
        if number in vetoers:
            return cls.VETOER
        elif number in banned:
            return cls.BANNED
        elif number in subscribers:
            return cls.SUBSCRIBED
        else:
            return cls.UNSUBSCRIBED

class InvalidNumber(ValueError):
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

    except InvalidNumber:
        return make_response("invalid", 406)

    if not (msg["src"] and msg["dst"] and msg["text"]):
        return make_response("missing parameter", 406)

    msg["text"] = msg["text"].strip()

    if not msg["text"]:
        print("\nIgnoring empty text")
        return make_response("empty", 406)

    db = get_db()

    user_type = UserType.from_number(msg["src"], subscribers=get_subscribers(), banned=get_banned(), vetoers=settings.vetoers)
    print("\nReceived SMS from {} ({}) to {}: {}".format(msg["src"], user_type.name.lower(), msg["dst"], msg["text"]))

    if user_type is UserType.BANNED:
        print("\nIgnoring banned user {}".format(msg["src"]))
        return responses.queued(msg["src"], msg["dst"])

    if msg["text"].lower() == "unstop":
        if user_type is UserType.UNSUBSCRIBED:
            subscribe(msg["src"])
            return responses.subscribed(msg["src"], msg["dst"])
        return responses.already_subscribed(msg["src"], msg["dst"])

    if msg["text"].lower() in commands.unsubscribe:
        if user_type is UserType.UNSUBSCRIBED:
            return responses.not_subscribed(msg["src"], msg["dst"])
        unsubscribe(msg["src"])
        return responses.unsubscribed(msg["src"], msg["dst"])

    if user_type is not UserType.UNSUBSCRIBED and msg["text"].lower() in commands.subscribe:
        return responses.already_subscribed(msg["src"], msg["dst"])

    if user_type is UserType.UNSUBSCRIBED and commands.has_subscribe_phrase(msg["text"]):
        subscribe(msg["src"])
        return responses.subscribed(msg["src"], msg["dst"])

    if user_type is not UserType.VETOER:
        msgid = enqueue(msg)
        inform(msgid, msg)
        return responses.queued(msg["src"], msg["dst"])

    # VETOER COMMANDS BELOW

    cmd = msg["text"].strip('"').split()
    try:
        if cmd[0].lower() in ("ok", "veto", "ban", "info"):
            msg_requested = db.execute("select src, dst, text from queue where id = ?", [cmd[1]]).fetchone()
            if msg_requested is None:
                return responses.nomsg(cmd[1], msg["src"], msg["dst"])

            if cmd[0].lower() == "info":
                return responses.inform(cmd[1], msg_requested["text"], msg["src"], msg["dst"])

            if cmd[0].lower() == "ok":
                if send_immediately(cmd[1]):
                    return responses.approved(cmd[1], msg["src"], msg["dst"])
                return responses.nomsg(cmd[1], msg["src"], msg["dst"])

            if dequeue(cmd[1]):
                if cmd[0].lower() == "ban":
                    ban(msg_requested["src"])
                    return responses.ban(cmd[1], msg_requested["src"], msg["src"], msg["dst"])
                return responses.vetoed(cmd[1], msg["src"], msg["dst"])
            return responses.nomsg(cmd[1], msg["src"], msg["dst"])

        if msg["text"].lower() in ("subscribers", "subscribed", "signups", "sign-ups", "signed up", "signed-up", "users"):
            return responses.subscribers(msg["src"], len(get_subscribers()), msg["dst"])

        if msg["text"].lower() == "investigators":
            return responses.vetoers(msg["src"], msg["dst"])

        if cmd[0].lower() == "investigators":
            wallops(" ".join(cmd[1:]), msg["src"], msg["dst"])
            return responses.wallops_ok(msg["src"], msg["dst"])

        if msg["text"].lower() == "queue":
            return responses.queue_status(msg["src"], get_queue(), msg["dst"])

        if msg["text"].lower() in ("banned", "bans"):
            return responses.banned(msg["src"], len(get_banned()), msg["dst"])

        if msg["text"].lower() == "ping":
            return responses.pong(msg["src"], msg["dst"])

    except IndexError:
        return responses.nomsgid(msg["src"], msg["dst"])

    # direct blast message
    blast(msg, from_vetoer=True)
    return responses.thank_you(msg["src"], msg["dst"])

app.register_blueprint(bp, url_prefix="/" + settings.root_key)

if __name__ == "__main__":
    t = Thread(target=queue_runner)
    t.start()
    app.run(host='0.0.0.0', port=settings.port)
