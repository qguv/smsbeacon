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

def ban(msgid, number_banned, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "{}: message {} vetoed and its sender ({}) banned by {}".format(settings.appname, msgid, number_banned, settings.vetoers[by]),
            number)

def approved(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "{}: message {} approved by {}".format(settings.appname, msgid, settings.vetoers[by]),
            number)

def subscribed(to, number):
    return xmlgen(to,
            "{}: you've subscribed, reply with the word unsubscribe to opt-out".format(settings.appname),
            number)

def not_subscribed(to, number):
    return xmlgen(to,
            "{}: you aren't subscribed, reply with the word subscribe to subscribe to updates".format(settings.appname),
            number)

def already_subscribed(to, number):
    return xmlgen(to,
            "{}: you're already subscribed, reply with the word unsubscribe to opt-out".format(settings.appname),
            number)

def thank_you(to, number):
    return xmlgen(to,
            "{}: we've sent out your report, thank you!".format(settings.appname),
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

def banned(to, n, number):
    return xmlgen(to, "{}: {} banned".format(settings.appname, n), number)

def queue_status(to, queue, number):
    return xmlgen(to, "{}: {} messages queued{}{}".format(settings.appname, len(queue), ": " if queue else "", ", ".join(map(str, queue))), number)

def vetoers(to, number):
    return xmlgen(to,
            "{}: {} vetoers: {}".format(
                settings.appname,
                len(settings.vetoers),
                ", ".join(sorted(settings.vetoers.values()))),
            number)

def pong(to, number):
    return xmlgen(to, "{}: pong".format(settings.appname), number)
