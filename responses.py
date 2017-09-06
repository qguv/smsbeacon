'''Plivo Messag XML support for smsbeacon'''

# internal

import utils
from xml.sax.saxutils import escape

# external

from flask import Response

def xmlgen(text, to, beacon_telno):
    if isinstance(to, str):
        to = [to]
    to = '<'.join(utils.normal_telno(t) for t in to if t != 'root')

    print("[DEBUG] Beacon at {} sending SMS to {} via XML response: \"{}\"".format(beacon_telno, to if to else "nobody", text))

    # plivo shits the bed if we send responses with no destination numbers
    if not to:
        return

    m = '<Response><Message dst="{}" src="{}">{}</Message></Response>'
    return Response(m.format(to, beacon_telno, escape(text)), mimetype="text/xml")

def now_subscribed(to, beacon_telno):
    return xmlgen("You are now subscribed!", to, beacon_telno)

def already_subscribed(to, beacon_telno):
    return xmlgen("You were already subscribed!", to, beacon_telno)

def blasted_thanks(to, beacon_telno):
    return xmlgen("Your report was sent out, thanks for submitting.", to, beacon_telno)

def submitted_thanks(to, beacon_telno):
    return xmlgen("We got your report, thanks for submitting.", to, beacon_telno)

def pong(to, beacon_telno):
    return xmlgen("pong", to, beacon_telno)
