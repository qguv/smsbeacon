from xml.sax.saxutils import escape
from flask import Response, make_response
import settings

def ignore():
    return make_response("um alright", 201)

def xmlgen(to, text, number):
    m = '<Response><Message dst="{}" src="{}">{}: {}</Message></Response>'
    return Response(m.format(to, number, escape(settings.appname), escape(text)), mimetype="text/xml")

def queued(to, number):
    return xmlgen(to, "report received", number)

def vetoed(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "message {} vetoed by {}".format(msgid, settings.vetoers[by]),
            number)

def ban(msgid, number_banned, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "message {} vetoed and its sender ({}) banned by {}".format(msgid, number_banned, settings.vetoers[by]),
            number)

def approved(msgid, by, number):
    return xmlgen("<".join(settings.vetoers.keys()),
            "message {} approved by {}".format(msgid, settings.vetoers[by]),
            number)

def subscribed(to, number):
    return xmlgen(to,
            "you've subscribed, reply with the word unsubscribe to opt-out",
            number)

def not_subscribed(to, number):
    return xmlgen(to,
            "you aren't subscribed, reply with the word subscribe to subscribe to updates",
            number)

def already_subscribed(to, number):
    return xmlgen(to,
            "you're already subscribed, reply with the word unsubscribe to opt-out",
            number)

def thank_you(to, number):
    return xmlgen(to,
            "we've sent out your report, thank you!",
            number)

def unsubscribed(to, number):
    return xmlgen(to, "you've unsubscribed", number)

def nomsg(msgid, to, number):
    return xmlgen(to,
        "no message with id {}".format(msgid),
        number)

def nomsgid(to, number):
    return xmlgen(to,
            "you forgot a message id: e.g. veto 28",
            number)

def blast(text, subscribers, by, number):
    dest = subscribers + list(settings.vetoers.keys())
    try:
        dest.remove(by)
    except ValueError:
        pass
    return xmlgen("<".join(dest), text, number)

def subscribers(to, n, number):
    return xmlgen(to, "{} subscribers, excluding vetoers".format(n), number)

def banned(to, n, number):
    return xmlgen(to, "{} banned".format(n), number)

def queue_status(to, queue, number):
    l = len(queue)
    plural = "" if l == 1 else "s"
    return xmlgen(to, "{} message{} queued{}{}".format(l, plural, " with id{}: ".format(plural) if l else "", ", ".join(map(str, queue))), number)

def vetoers(to, number):
    return xmlgen(to,
            "{} vetoers: {}".format(
                len(settings.vetoers),
                ", ".join(sorted(settings.vetoers.values()))),
            number)

def pong(to, number):
    return xmlgen(to, "pong", number)
