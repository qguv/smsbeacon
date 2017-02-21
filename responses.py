from xml.sax.saxutils import escape
from flask import Response, make_response
import settings

def ignore():
    return make_response("um alright", 201)

def xmlgen(to, text, number):
    m = '<Response><Message dst="{}" src="{}">{}</Message></Response>'
    return Response(m.format(to, number, escape(text)), mimetype="text/xml")

def queued(to, number):
    return xmlgen(to, "{}: report received".format(settings.appname), number)

def vetoed(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "{}: message {} vetoed by {}".format(settings.appname, msgid, settings.vetoers[by]),
            number)

def banned(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "{}: message {} vetoed and its sender banned by {}".format(settings.appname, msgid, settings.vetoers[by]),
            number)

def approved(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "{}: message {} approved by {}".format(settings.appname, msgid, settings.vetoers[by]),
            number)

def subscribed(to, number):
    return xmlgen(to,
            "{}: you've subscribed, send unsubscribe to opt-out".format(settings.appname),
            number)

def unsubscribed(to, number):
    return xmlgen(to, "{}: you've unsubscribed".format(settings.appname), number)

def nomsg(msgid, to, number):
    return xmlgen(to,
        "{}: no message with id {}".format(settings.appname, msgid),
        number)

def nomsgid(to, number):
    return xmlgen(to,
            "{}: you forgot a message id: e.g. veto 28".format(settings.appname),
            number)

def blast(text, subscribers, by, number):
    dest = subscribers + list(settings.vetoers.keys())
    dest.remove(by)
    return xmlgen("<".join(subscribers), "{}: {}".format(settings.appname, text), number)

def subscribers(to, n, number):
    return xmlgen(to, "{}: {} subscribers".format(settings.appname, n), number)

def vetoers(to, number):
    return xmlgen(to,
            "{}: {} vetoers: {}".format(
                settings.appname,
                len(settings.vetoers),
                ", ".join(sorted(settings.vetoers.values()))),
            number)

def pong(to, number):
    return xmlgen(to, "{}: pong".format(settings.appname), number)
