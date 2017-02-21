#!/usr/bin/env python3

from flask import Flask, request, make_response
import plivo

from time import sleep
from threading import Thread
from pprint import pprint
import shelve

import settings
import responses

app = Flask(__name__)
p = plivo.RestAPI(settings.plivo_id, settings.plivo_token)

open_queue = lambda: shelve.open("{}.shelf".format(settings.appname))
with open_queue() as queue:
    if "next_id" not in queue:
        queue["next_id"] = 0
    if "subscribers" not in queue:
        queue["subscribers"] = settings.initial_subscribers
    if "banned" not in queue:
        queue["banned"] = []

def blast(msg, subscribers):
    dest = subscribers[:]
    try:
        dest.remove(msg["src"])
    except ValueError:
        pass
    p.send_message({"src": msg["dst"],
                    "dst": "<".join(subscribers),
                    "text": "{}: {}".format(settings.appname, msg["text"])})

def inform(msgid, msg):
    p.send_message({"src": msg["dst"],
                    "dst": "<".join(settings.vetoers.keys()),
                    "text": '{}: ok/veto/ban {}? "{}"'.format(settings.appname, msgid, msg["text"])})

def enqueue(msg):
    msg["delay"] = settings.veto_delay
    with open_queue() as queue:
        msgid = queue["next_id"]
        queue[str(msgid)] = msg
        queue["next_id"] = msgid + 1
    return msgid

def dequeue(msgid: str) -> bool:
    with open_queue() as queue:
        try:
            del queue[msgid]
            return True
        except KeyError:
            return False

def send_immediately(msgid: str) -> bool:
    with open_queue() as queue:
        try:
            msg = queue[msgid]
            blast(msg, queue["subscribers"])
            del queue[msgid]
            return True
        except KeyError:
            return False

def queue_runner():
    while True:
        sleep(settings.queue_interval)

        # beware funky mutate semantics; queue can't mutate in-place!
        to_delete = []
        with open_queue() as queue:

            for msgid in queue:
                if msgid in ("next_id", "subscribers", "banned"):
                    continue

                msg = queue[msgid]
                if msg["delay"] <= 1:
                    print("blasting queued message")
                    blast(msg, queue["subscribers"])
                    to_delete.append(msgid)
                else:
                    msg["delay"] -= 1
                    queue[msgid] = msg

            for msgid in to_delete:
                del queue[msgid]

@app.route('/test/', methods=['GET'])
def test():
    return "OK"

@app.route('/receive_sms/', methods=['GET', 'POST'])
def receive_sms():
    msg = {
            "src": request.values.get('From'),
            "dst": request.values.get('To'),
            "text": request.values.get('Text').strip(),
    }

    pprint(msg)

    if msg["src"] is None or msg["dst"] is None or msg["text"] is None:
        return make_response("something's missing", 403)

    with open_queue() as queue:

        if msg["src"] in queue["banned"] or not msg["text"]:
            print("ignoring banned user")
            return responses.ignore()

        if msg["text"].lower() in ("stop", "unsubscribe"):
            if msg["src"] not in queue["subscribers"]:
                return responses.ignore()
            subs = queue["subscribers"]
            try:
                subs.remove(msg["src"])
                queue["subscribers"] = subs
                print("unsubscribed")
            except ValueError:
                return responses.ignore()
            return responses.unsubscribed(msg["src"], msg["dst"])

        if msg["text"].lower() == "subscribe":
            if msg["src"] in queue["subscribers"] or msg["src"] in settings.vetoers:
                return responses.ignore()
            subs = queue["subscribers"]
            subs.append(msg["src"])
            queue["subscribers"] = subs
            print("subscribed")
            return responses.subscribed(msg["src"], msg["dst"])

        if msg["src"] not in settings.vetoers:
            msgid = enqueue(msg)
            inform(msgid, msg)
            print("message queued")
            return responses.queued(msg["src"], msg["dst"])

        cmd = msg["text"].strip('"').split()
        try:

            if cmd[0].lower() == "ban":
                to_ban = queue[cmd[1]]["src"]
                if dequeue(cmd[1]):
                    banned = queue["banned"]
                    banned.append(to_ban)
                    queue["banned"] = banned
                    subs = queue["subscribers"]
                    try:
                        subs.remove(to_ban)
                        queue["subscribers"] = subs
                    except ValueError:
                        return responses.ignore()
                    print("message vetoed and user banned!")
                    return responses.banned(cmd[1], msg["src"], msg["dst"])
                else:
                    return responses.nomsg(cmd[1], msg["src"], msg["dst"])

            # veto for msgid
            if cmd[0].lower() == "veto":
                if dequeue(cmd[1]):
                    print("message vetoed!")
                    return responses.vetoed(cmd[1], msg["src"], msg["dst"])
                else:
                    return responses.nomsg(cmd[1], msg["src"], msg["dst"])

            # queue override for msgid
            if cmd[0].lower() == "ok":
                if send_immediately(cmd[1]):
                    print("message explicitly approved")
                    return responses.approved(cmd[1], msg["src"], msg["dst"])
                else:
                    return responses.nomsg(cmd[1], msg["src"], msg["dst"])

            if msg["text"].lower() == "subscribers":
                return responses.subscribers(msg["src"], len(queue["subscribers"]), msg["dst"])

            if msg["text"].lower() == "vetoers":
                return responses.vetoers(msg["src"], msg["dst"])

            if msg["text"].lower() == "ping":
                return responses.pong(msg["src"], msg["dst"])

        except IndexError:
            return responses.nomsgid(msg["src"], msg["dst"])

        # direct blast message
        print("directly blasting message from vetoer")
        return responses.blast(msg["text"], queue["subscribers"], msg["src"], msg["dst"])

if __name__ == "__main__":
    t = Thread(target=queue_runner)
    t.start()
    app.run(host='0.0.0.0', port=80)
