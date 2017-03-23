# Beacon over SMS

Receive and rebroadcast SMS messages with a short veto delay.

## use

Send a text to a number registered with Plivo, and Beacon will forward it to a set group of vetoers. If it's appoved, or not vetoed in a short amount of time, then it will be sent out to all subscribers.

### commands
- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- anything else is added to a queue for a short time to allow spam to be vetoed; after that, it will be sent to all subscribers

### vetoer commands

- `vetoers`: who is currently listed as a vetoer
- `subscribers`: how many non-vetoers are signed up
- `ping`: will reply "pong"
- `ok 24`: approves message 24 in the queue to be sent immediately to subscribers
- `veto 24`: vetos message 24 in the queue, preventing it from being sent to subscribers
- `ban 24`: vetos message 24 in the queue and bans its author, preventing it from being sent to subscribers
- anything else is treated like a direct message blast, sent directly to all subscribers and vetoers without going through the queue

## spin up your own

- get a [plivo][] account and buy a number or two; note your plivo id and auth token
- clone this repository
- put your plivo id and auth token in settings.py
- add vetoers in settings.py (especially for your testing cell phone)
- `FLASK_APP=app.py flask initdb`
- run app.py as a daemon on a machine with port 80 publicly accessible
- go to plivo and tell the plivo number's connected application the address of your machine running app.py
- text `ping` to your plivo number from a vetoer number
- get everyone to subscribe

[plivo]: (https://plivo.com/)
