# Beacon over SMS

Receive and rebroadcast SMS messages with a short veto delay.

## use

Send a text to a number registered with Plivo, and Beacon will forward it to a set group of investigators. If it's appoved, or not responded to quickly by an investigator, then it will be sent out to all subscribers.

### commands

- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- `unstop`: resubscribe after you've unsubscribed; you might need to send this twice. **If beacon isn't responding after you've unsubscribed, try unstop!**
- anything else is added to a queue for a short time to allow people to investigate; after that, it will be sent to all subscribers

### investigator commands

Users registered as "investigators" also have access to the following commands:

- `yes 24`: indicates that you're looking into message 24; queued time will be dramatically increased
- `no 24`: indicates that you can't look into message 24; does not affect queued time
- `approve 24`: approves message 24 in the queue to be sent immediately to subscribers
- `veto 24`: vetos message 24 in the queue, preventing it from being sent to subscribers
- `ban 24`: vetos message 24 in the queue and bans its author, preventing it from being sent to subscribers
- `queue`: shows how many messages are in the message queue and their ids
- `investigators some text here`: sends "some text here" to all investigators but not regular subscribers
- `investigators`: who is currently listed as a investigator
- `subscribers`: how many people are signed up
- `banned`: how many numbers are banned
- `ping`: will reply "pong" (useful for testing)
- anything else is treated like a direct message blast, sent directly to all subscribers and investigators without going through the queue. **Careful with this one!**

## spin up your own

- clone this repository on a webserver
- get a [plivo][] account and buy a number or two
- put your plivo id and auth token in settings.py
- spin up a mariadb or mysql database somewhere and put the info in settings.py
- also in settings.py, set `root_key` to a randomly generated long alphanumeric string
- add plivo number, instance name, and default investigator/subscriber/banned information in settings.py
- `FLASK_APP=app.py flask initdb`
- run app.py as a daemon; make sure port 80 is publicly accessible
- go to plivo and set the plivo number's connected application to the address of your webserver, with the route:

```
http://your-server-ip-or-domain:your_port/your_root_key/
```

- text `ping` to your plivo number from a vetoer number; if it replies `pong`, you're good to go
- get everyone in the area to subscribe

[plivo]: (https://plivo.com/)

## spinning up your own on AWS

- get yourself an RDS instance running mariadb
- spin yourself up an ec2 server and run `pip3 install PyMySQL`
- follow "spin up your own" steps above

## troubleshooting

First, can you access `http://your-server-ip-or-domain:your_port/test` in a browser?

If the server times out, the server is not running, or else the port is blocked on the server with a firewall or in network hardware, or else there is some server misconfiguration.

If you're getting 403 "forbidden", check permissions, especially of the user running the server. If you're using a port less than 1024, you need to have superuser privileges on most unix systems.

If you're getting 503 "internal server errors", check the output of the process running app.py for more information.

Otherwise I don't know what's wrong. Throw a sysadmin some candy and approach them slowly, maybe they'll help if they don't see you as a threat.
