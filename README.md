# smsbeacon 2.0.0

Receive and rebroadcast SMS messages with a short veto delay.

_shiny second version with greatly improved administration/investigation!_

## use

Send a text to a number registered with Plivo, and the beacon will forward it to a set group of investigators. If it's appoved, or not vetoed after a while, then it will be sent out to all subscribers.

### sms commands

- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- `unstop`: resubscribe after you've unsubscribed; you might need to send this twice. **If beacon isn't responding after you've unsubscribed, try unstop!**
- anything else is added to a queue for a short time to allow spam to be vetoed; after that, it will be sent to all subscribers

## how it works

Each beacon server can support as many beacons as you'd like. There are two ways to get started:

### jumping onto my beacon server

I ([qguv](https://github.com/qguv)) run a beacon server for community use. If your non-business, non-government, not-for-profit group wants a beacon, please get in touch with me.

### spinning up your own manually

- get a [plivo][] account and buy a number; note your plivo id and auth token
- set up the database:
  - spin up a mysql instance accessable over the public internet
  - create a new `smsbeacon` database in mysql
  - make a password-protected user with permission to access and modify the `smsbeacon` database
- configure AWS for serverless:
  - `npm install -g serverless serverless-wsgi serverless-python-requirements`
  - follow [this doc](https://serverless.com/framework/docs/providers/aws/guide/credentials)
- deploy the code:
  - clone this repository on your dev machine
  - modify `config.py` to reflect your database information
  - change the `change me` fields in `config.py` to long, random strings ([random.org][] is okay)
  - `serverless deploy -v`
- configure your beacon on the site:
  - run `./init_db.py`, note the URL it gives you
  - go to the URL given in the previous step and set the root password
  - click the link to create a new beacon
  - fill in the information, including the plivo id and auth token from earlier
  - copy the text it gives you and paste it into the plivo number's connected application field; this is the URL plivo uses to send incoming SMS messages to your beacon
  - add yourself as an admin and set your own password
- test it:
  - from the admin phone number you entered, text `ping` to the number you registered with plivo; if you've done everything right, you should get `pong` back
  - tell everyone who matters to subscribe

[plivo]: https://plivo.com/
[random.org]: https://www.random.org/passwords/?num=100&len=32&format=html&rnd=new

## troubleshooting

First, can you access `http://your-server-ip-or-domain/test` in a browser? If so, the code is at least runnable. Check to see if you have a database or Plivo configuration issue.

If you're getting 503 "internal server error", check AWS lambda logs for more information.
