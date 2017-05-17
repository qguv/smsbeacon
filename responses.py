from xml.sax.saxutils import escape
from flask import Response
import settings

def xmlgen(name, to, text, number):
    m = '<Response><Message dst="{}" src="{}">{}: {}</Message></Response>'
    return Response(m.format(to, number, escape(settings.appname), escape(text)), mimetype="text/xml")

def queued(name, to, number):
    return xmlgen(name, to, "report received", number)

def vetoed(name, msgid, by, number, investigators: dict):
    return xmlgen(name, "<".join(investigators.keys()),
            "message {} vetoed by {}".format(msgid, investigators[by]),
            number)

def ban(name, msgid, number_banned, by, number, investigators: dict):
    return xmlgen(name, "<".join(investigators.keys()),
            "message {} vetoed and its sender ({}) banned by {}".format(msgid, number_banned, investigators[by]),
            number)

def approved(name, msgid, by, number, investigators: dict):
    return xmlgen(name, "<".join(investigators.keys()),
            "message {} approved by {}".format(msgid, investigators[by]),
            number)

def subscribed(name, to, number):
    return xmlgen(name, to,
            "you've subscribed, reply with the word unsubscribe to opt-out",
            number)

def not_subscribed(name, to, number):
    return xmlgen(name, to,
            "you aren't subscribed, reply with the word subscribe to subscribe to updates",
            number)

def already_subscribed(name, to, number):
    return xmlgen(name, to,
            "you're already subscribed, reply with the word unsubscribe to opt-out",
            number)

def thank_you(name, to, number):
    return xmlgen(name, to,
            "we've sent out your report, thank you!",
            number)

def good_luck(name, msgid, to, number):
    return xmlgen(name, to,
            "Delay extended. Remember to approve {} or veto {} once you've confirmed/denied the report. Good luck.".format(msgid, msgid),
            number)

def ack_cant_go(name, to, number):
    return xmlgen(name, to, "got it, that's okay", number)

def unsubscribed(name, to, number):
    return xmlgen(name, to, "you've unsubscribed", number)

def nomsg(name, msgid, to, number):
    return xmlgen(name, to,
        "no message with id {}".format(msgid),
        number)

def nomsgid(name, to, number):
    return xmlgen(name, to,
            "you forgot a message id: e.g. veto 28",
            number)

def wallops_ok(name, to, number):
    return xmlgen(name, to, "message sent to investigators", number)

def subscribers(name, to, n, number):
    return xmlgen(name, to, "{} subscribers".format(n), number)

def banned(name, to, n, number):
    return xmlgen(name, to, "{} banned".format(n), number)

def queue_status(name, to, queue, number):
    l = len(queue)
    plural = "" if l == 1 else "s"
    return xmlgen(name, to, "{} message{} queued{}{}".format(l, plural, " with id{}: ".format(plural) if l else "", ", ".join(map(str, queue))), number)

def investigators(name, to, number, investigators: dict):
    return xmlgen(name, to,
            "{} investigators: {}".format(
                len(investigators),
                ", ".join(sorted(investigators.values()))),
            number)

def pong(name, to, number):
    return xmlgen(name, to, "pong", number)
