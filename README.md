# smsbeacon 2.0.0

Receive and rebroadcast SMS messages with a short veto delay.

_shiny second version with greatly improved administration/investigation!_

## use

Send a text to a number registered with Plivo, and the beacon will forward it to a set group of investigators. If it's appoved, or not vetoed after a while, then it will be sent out to all subscribers.

### sms commands

- `subscribe`: sign up to get alerts
- `unsubscribe`: opt out of alerts; you might not get confirmation
- `resume`: resubscribe after you've unsubscribed; you might need to send this twice. **If your beacon isn't responding after you've unsubscribed, try sending resume!**
- anything else is added to a queue for a short time to allow spam to be vetoed; after that, it will be sent to all subscribers

## how it works

Each smsbeacon server can support as many beacons as you'd like. There are two ways to get started:

### jumping onto my beacon server

I ([qguv](https://github.com/qguv)) run a beacon server for community use. If your non-business, non-government, not-for-profit group wants a beacon, please get in touch with me.

### spinning up your own manually

- get some numbers
  - open a [plivo][] account
  - create a subaccount for the smsbeacon called, uh, `smsbeacon`
  - look up that account's API ID and token, note them somewhere
- set up the database:
  - spin up a mysql instance accessable over the public internet
  - create a new `smsbeacon` database in mysql
  - make a password-protected user with permission to access and modify the `smsbeacon` database
- configure AWS for serverless:
  - `sudo npm install -g serverless`
  - `npm install --save serverless-wsgi`
  - follow [this doc](https://serverless.com/framework/docs/providers/aws/guide/credentials)
- deploy the code:
  - clone this repository on your dev machine
  - `pip3 install virtualenv pymysql passlib`, some deployment dependencies
  - modify `config.py` to reflect your database information, public URL, etc
  - change the `change me` fields in `config.py` to [long random strings][random]
  - get a (free) Amazon SSL certificate for your (sub)domain
  - set up a custom domain in [API Gateway](https://console.aws.amazon.com/apigateway/home?region=us-east-1#/custom-domain-names) for the domain you just SSL'd
  - with your domain's DNS provider (probably where you bought your domain), set up a CNAME record to the cloudfront URL you're given in API Gateway
  - `serverless deploy` and you're _done_
- configure your beacon on the site:
  - run `./init_db.py`, note the URL it gives you
  - go to the URL given in the previous step and set the root password to [something random and fairly long][random]
  - click the link to create a new beacon
  - fill in the information, including the plivo id and auth token from earlier
  - copy the url it gives you after you submit and paste it into the message field in the plivo number's connected application; this is the URL plivo uses to send incoming SMS messages to your beacon
  - **IMPORTANT**: add your phone number as an admin, then follow the texted link to set your password
- test it:
  - from the admin phone number you entered, text `ping` to the number you registered with plivo; if you've done everything right, you should get `pong` back
  - tell everyone who matters to subscribe

[plivo]: https://plivo.com/
[random]: https://www.random.org/passwords/?num=100&len=24&format=html&rnd=new

## troubleshooting

First, can you access `http://your-server-ip-or-domain/test` in a browser? If so, the code is at least runnable. Check to see if you have a database or Plivo configuration issue.

If you're getting 503 "internal server error", check AWS lambda logs for more information.
