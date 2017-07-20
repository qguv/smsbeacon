# smsbeacon 2.0.0

Receive and rebroadcast SMS messages with a short veto delay.

_shiny second version with greatly improved administration/investigation!_

## use

Send a text to a number registered with Plivo, and Beacon will forward it to a set group of investigators. If it's appoved, or not vetoed in a short amount of time, then it will be sent out to all subscribers.

### sms commands

- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- `unstop`: resubscribe after you've unsubscribed; you might need to send this twice. **If beacon isn't responding after you've unsubscribed, try unstop!**
- anything else is added to a queue for a short time to allow spam to be vetoed; after that, it will be sent to all subscribers

## spin up your own

- get a [plivo][] account and buy a number; note your plivo id and auth token
- clone this repository on a webserver
- spin up a mysql instance and point the app to it in settings.py
- create a new `smsbeacon` database in mysql and give a user permission to access and modify it
- `mysql -h YOURHOST -u YOURUSER -pYOURPASS smsbeacon < schema.sql`
- `FLASK_APP=app.py flask initdb`, note the URL it gives you
- run app.py as a daemon; make sure port 80 is publicly accessible
- go to the URL given in the previous step and set the root password
- click the link to create a new beacon
- fill in the information, including the plivo id and auth token from earlier. don't forget to add yourself as an admin!
- copy the text it gives you and paste it into the plivo number's connected application field
- text `ping` to the number you registered as an admin; you should get `pong` back if it's working
- get everyone to subscribe

[plivo]: (https://plivo.com/)

## troubleshooting

First, can you access `http://your-server-ip-or-domain/test` in a browser?

If the server times out, the server is not running, or else the port is blocked on the server with a firewall or in network hardware, or else there is some server misconfiguration.

If you're getting 403 "forbidden", check permissions, especially of the user running the server. If you're using a port less than 1024, you need to have superuser privileges on most unix systems.

If you're getting 503 "internal server errors", check the output of the process running app.py for more information.
