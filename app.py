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

open_queue = lambda: shelve.open(settings.appname)
with open_queue() as queue:
    if "next_id" not in queue:
        queue["next_id"] = 0

def blast(msg):
    p.send_message({"src": settings.plivo_number,
                    "dst": "<".join(settings.subscribers),
                    "text": "{}: {}".format(settings.appname, msg["text"])})

def inform(msgid, msg):
    p.send_message({"src": settings.plivo_number,
                    "dst": "<".join(settings.vetoers.keys()),
                    "text": '{}: new report follows, reply "ok {}" to confirm it or "veto {}" to reject it'.format(settings.appname, msgid, msgid)})
    p.send_message({"src": settings.plivo_number,
                    "dst": "<".join(settings.vetoers.keys()),
                    "text": "{}: ({}) {}".format(settings.appname, msgid, msg["text"])})

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
            blast(msg)
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
                if msgid == "next_id":
                    continue

                msg = queue[msgid]
                if msg["delay"] <= 1:
                    blast(msg)
                    to_delete.append(msgid)
                else:
                    msg["delay"] -= 1
                    queue[msgid] = msg

            for msgid in to_delete:
                del queue[msgid]

@app.route('/test/', methods=['GET'])
def test():
    return "OK"

@app.route('/sms/rx/', methods=['GET', 'POST'])
def receive():
    msg = {
            "src": request.values.get('From'),
            "dst": request.values.get('To'),
            "text": request.values.get('Text'),
    }

    pprint(msg)

    if msg["src"] is None or msg["dst"] is None or msg["text"] is None:
        return make_response("something's missing", 403)

    if msg["src"] not in settings.vetoers:
        msgid = enqueue(msg)
        inform(msgid, msg)
        return responses.queued(msg["src"])

    cmd = msg["text"].strip('"').split()
    try:

        # veto for msgid
        if cmd[0] == "veto":
            if dequeue(cmd[1]):
                return responses.vetoed(cmd[1], msg["src"])
            else:
                return responses.nomsg(cmd[1], msg["src"])

        # queue override for msgid
        if cmd[0] == "ok":
            if send_immediately(cmd[1]):
                return responses.approved(cmd[1], msg["src"])
            else:
                return responses.nomsg(cmd[1], msg["src"])

    except IndexError:
        return responses.nomsgid(msg["src"])

    # direct blast message
    return responses.blast(msg["text"])

if __name__ == "__main__":
    t = Thread(target=queue_runner)
    t.start()
    app.run(host='0.0.0.0', port=80)
