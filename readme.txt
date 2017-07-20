,=======,
|| API ||
'======='

,--------------------,
| Routes before auth |
'--------------------'

GET/POST /tick/{tick_secret}
	for beacon in db.beacons.where(b => b.autosend == after_delay)
		for alert in db.alerts.where(a => a.beacon == beacon)
			if alert.reported + beacon.autosend_delay <= now()
				blast alert
			if alert.sent and alert.sent + beacon.prune_delay <= now()
				delete alert
		db.alerts.commit()

GET/POST /sms/{secret}
Src telno
Dst telno
Text string
	beacon = db.beacon.where(b => b.secret == secret)
	if not beacon:
		code 401
	user = db.users.where(u => u.beacon == beacon.beacon and request.Src == u.user)
	if user.role in (Role.banned_subscribed, Role.banned_not_subscribed)
		code 200
	if match_unsubscribe(request.Text)
		if user.role == Role.admin
			render "no, you're an admin!"
		if user.role == Role.subscribed
			user.role = Role.not_subscribed
			defer db.users.commit()
			render "unsubscribed, text subscribe to subscribe"
	if match_subscribe(request.Text)
		if user.role == Role.admin
			render "you're already an admin!"
		if user.role == Role.unsubscribed
			user.role = Role.subscribed
			defer db.users.commit()
		render "subscribed, text xyz to unsubscribe"
	if user.role is admin
		make_token(user)
		render "to send a message, go to https://smsbeacon/{make_token(user)}/alerts/new"
		blastees = query db for Dst subscribers & admins
		remove Src from blastees
		blast message to blastees
		render "message posted"
	commit request to db
	blast notification to admins
	render "thank you for your report"

GET /{loc}
	render form to POST /{loc}

POST /{loc}
user telno
pass string
	beacon = db.beacons.where(b => b.locid == loc)
	if not beacon
		code 404
	concurrently
		user = db.users.where(u => u.beacon == beacon.beacon and u.user == request.user)
		phash = hash_with_salt(request.pass, beacon.salt)
	if user.phash != phash
		return 403
	cookie
	redirect /{loc}/alerts

GET /{loc}/login
GET /{loc}/login/{token}

GET /{token}/{*}
	user = db.users.where(u => u.token == token)
	if user:
		beacon = db.beacon.where(b => b.beacon == user.beacon)
	if (not user) or user.token + beacon.token_lifetime <= now()
		return 401
	store_cookie(user)
	redirect /{loc}/{*}

store_cookie(user, loc)
	make_token(user)
	store cookie(site=smsbeacon/loc, token=user.token)

,-------------,
| Behind auth |
'-------------'

GET /root/{token}
	check token
	make a new token and set as cookie
	redirect to /root

GET /root
	link to /beacons and /beacons/new
	render form to POST /root

POST /root
password
	commit to db
	redirect /beacons/new

GET /beacons

GET /beacons/new

POST /beacons/new

GET /{loc}/{token}

GET /{loc}/settings

POST /{loc}/settings

GET /{loc}/alerts
	query db for pending & recently sent alerts
	render them

GET /{loc}/alerts/new
	render form to POST /loc/alerts/new

POST /{loc}/alerts/new
	commit to db
	redirect /a/alerts

PATCH /a/alerts/{id}
	determine accept/reject
	commit to db
	redirect /a/alerts

---

GET /a/bans
	query db for banned users
	render them

GET /a/bans/new
	render form to POST /a/bans/new

PUT /a/bans/{number}
	query db for user {number}
	commit to db
	redirect /a/bans

DELETE /a/bans/{number}
	if number is admin
		code 403
	commit to db
	redirect /a/bans

---

GET /a/stats
	query db a bunch
	calculate some stats
	render them

,=======,
|| Web ||
'======='

- login form to POST /a
- list of alerts
  - ok -> POST
  - veto -> DELETE
  - ban -> DELETE then DELETE
- list of bans

,=======,
|| SMS ||
'======='

Text to Plivo number makes rest call to webapp with unique {secret}.
