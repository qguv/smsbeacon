from xml.sax.saxutils import escape
from flask import Response
import settings

def make_response(to, text):
    m = '<Response><Message dst="{}" src="{}">{}</Message></Response>'
    return Response(m.format(to, settings.plivo_number, escape(text), mimetype="text/xml"))

def queued(to):
    return make_response(to,
            "{}: report received".format(settings.appname))

def vetoed(msgid, by):
    return make_response("<".join(settings.vetoers.keys()),
            "{}: message {} vetoed by {}".format(settings.appname, msgid, settings.vetoers[by]))

def approved(msgid, by):
    return make_response("<".join(settings.vetoers.keys()),
            "{}: message {} approved by {}".format(settings.appname, msgid, settings.vetoers[by]))

def subscribed(to):
    return make_response(to,
            "{}: you've subscribed. Send STOP to opt-out".format(settings.appname))

def unsubscribed(to):
    return make_response(to,
            "{}: you've unsubscribed".format(settings.appname))

def nomsg(msgid, to):
    return make_response(to,
        "{}: no message with id {}".format(settings.appname, msgid))

def nomsgid(to):
    return make_response(to,
            "{}: you forgot a message id: e.g. veto 28".format(settings.appname))

def blast(text):
    return make_response("<".join(settings.subscribers),
            "{}: {}".format(settings.appname, text))
