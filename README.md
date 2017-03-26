# Beacon over SMS

Receive and rebroadcast SMS messages with a short veto delay.

## use

Send a text to a number registered with Plivo, and Beacon will forward it to a set group of vetoers. If it's appoved, or not vetoed in a short amount of time, then it will be sent out to all subscribers.

### commands
- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- `unstop`: resubscribe after you've unsubscribed; you might need to send this twice. **If beacon isn't responding after you've unsubscribed, try unstop!**
- anything else is added to a queue for a short time to allow spam to be vetoed; after that, it will be sent to all subscribers

### vetoer commands

Users registered as "vetoers" also have access to the following commands:

- `ok 24`: approves message 24 in the queue to be sent immediately to subscribers
- `veto 24`: vetos message 24 in the queue, preventing it from being sent to subscribers
- `ban 24`: vetos message 24 in the queue and bans its author, preventing it from being sent to subscribers
- `info 24`: shows the contents of message 24 in the queue
- `queue`: shows how many messages are in the message queue and their ids
- `vetoers some text here`: sends "some text here" to all vetoers but not regular subscribers
- `vetoers`: who is currently listed as a vetoer
- `subscribers`: how many non-vetoers are signed up
- `banned`: how many numbers are banned
- `ping`: will reply "pong" (useful for testing)
- anything else is treated like a direct message blast, sent directly to all subscribers and vetoers without going through the queue. **Careful with this one!**

## spin up your own

- get a [plivo][] account and buy a number or two; note your plivo id and auth token
- clone this repository on a webserver
- put your plivo id and auth token in settings.py
- also in settings.py, set `root_key` to a randomly generated long alphanumeric string
- add vetoers and default subscribers in settings.py (especially for your testing cell phone)
- `FLASK_APP=app.py flask initdb`
- run app.py as a daemon; make sure port 80 is publicly accessible
- go to plivo and set the plivo number's connected application to the address of your webserver, with the route:

```
http://your-server-ip-or-domain:your_port/your_root_key
```

- text `ping` to your plivo number from a vetoer number
- get everyone to subscribe

[plivo]: (https://plivo.com/)

## troubleshooting

First, can you access `http://your-server-ip-or-domain/test` in a browser?

If the server times out, the server is not running, or else the port is blocked on the server with a firewall or in network hardware, or else there is some server misconfiguration.

If you're getting 403 "forbidden", check permissions, especially of the user running the server. If you're using a port less than 1024, you need to have superuser privileges on most unix systems.

If you're getting 503 "internal server errors", check the output of the process running app.py for more information.

Otherwise I don't know what's wrong. Throw a sysadmin some candy and approach them slowly, maybe they'll help if they don't see you as a threat.
