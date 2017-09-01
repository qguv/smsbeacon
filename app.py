#!/usr/bin/env python3

import config
import forms
from db import Database, UserType, AlertType, ROOT_UID
from utils import random_token, all_of_them

from datetime import datetime
from functools import wraps
from collections import Counter
import pymysql

from passlib.context import CryptContext
crypto = CryptContext(schemes=['pbkdf2_sha256'])

#import plivo
#p = plivo.RestAPI(config.plivo_id, config.plivo_token)

from flask import Flask, request, render_template, g, url_for, redirect, \
    make_response, get_flashed_messages, flash
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.secret_key = config.flask_secret_key
csrfp = CSRFProtect(app)

def bad_request():
    return make_response(('Bad request :(', 400, {}))

def unauthorized():
    return make_response(('Unauthorized :(', 401, {}))

def forbidden():
    return make_response(('Forbidden :(', 403, {}))

def not_found():
    return make_response(('Not Found :(', 404, {}))

def get_db():
    if not hasattr(g, 'db'):
        g.db = Database()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def user_locid(uid) -> 'locid' or Exception:
    if uid == ROOT_UID:
        return 'root'

    sql = '''select b.locid
             from users u inner join beacon b
             where u.uid=%s'''

    return get_db().fetchone(sql, uid)[0].lower()

def user_uid(locid, telno) -> 'uid' or Exception:
    locid = locid.lower()
    if 'root' in (locid, telno):
        return ROOT_UID

    sql = '''select u.uid
             from users u inner join beacon b
             on u.beacon = b.telno
             where b.locid=%s and u.telno=%s'''

    return get_db().fetchone(sql, locid, telno)[0]

def user_telno(uid) -> 'telno' or Exception:
    if uid == ROOT_UID:
        return 'root'

    sql = '''select telno
             from users u
             where id=%s'''

    return get_db().fetchone(sql, uid)[0]

def user_type(uid) -> UserType or Exception:
    if uid == ROOT_UID:
        return UserType.ADMIN

    sql = '''select user_type
             from users u
             where id=%s'''

    return UserType(get_db().fetchone(sql, uid)[0])

def users_of_type(locid, *user_types) -> {"telno": "nickname" or None}:
    conditions = " or ".join([ "u.user_type = {}".format(int(user_type))
                               for user_type in user_types ])
    sql = '''select u.telno, u.nickname
             from users u inner join beacons b
             on u.beacon = b.telno
             where b.locid = %s
             and ({})'''.format(conditions)

    return { telno: nickname for telno, nickname in get_db().fetchall(sql, locid) }

def beacon_nickname(locid) -> str:
    sql = '''select nickname
             from beacons
             where locid = %s'''

    try:
        return get_db().fetchone(sql, locid)[0]
    except:
        return ''

def beacon_telno(locid) -> str:
    sql = '''select telno
             from beacons
             where locid = %s'''

    return get_db().fetchone(sql, locid)[0]

def beacon_autosend_delay(locid) -> int:
    sql = 'select autosend_delay from beacons where locid = %s'
    return get_db().fetchone(sql, locid)[0]

def beacon_prune_delay(locid) -> int:
    sql = 'select prune_delay from beacons where locid = %s'
    return get_db().fetchone(sql, locid)[0]

def alert_details(aid) -> ('text', 'sender'):
    sql = 'select text, telno from alerts where id = %s'
    return get_db().fetchone(sql, aid)

def user_token_lifetime(uid):
    sql = '''select b.token_lifetime
             from beacons b inner join users u
             on b.telno = u.beacon
             where u.id=%s'''

    return get_db().fetchone(sql, uid)[0]

def replace_token(uid) -> 'token':
    if uid == ROOT_UID:
        token_lifetime = config.root_token_lifetime
    else:
        token_lifetime = user_token_lifetime()

    token = random_token()

    updates = dict(
            thash = crypto.hash(token),
            token_expires = int(datetime.now().timestamp()) + token_lifetime)
    wheres = dict(id = uid)

    get_db().update('users', updates, wheres)
    return token

class BadToken(Exception):
    pass

class TokenExpired(Exception):
    pass

class NoSuchUser(Exception):
    pass

def token_auth(uid, token) -> None or Exception or BadToken or TokenExpired:
    '''TokenExpired implies the token would've otherwise been good. BadToken
    means the token failed the check, regardless of expiry.'''

    sql = '''select thash, token_expires
             from users
             where id=%s'''

    try:
        thash, token_expires = get_db().fetchone(sql, uid)
    except:
        raise Exception("couldn't get user")

    if not crypto.verify(token, thash):
        raise BadToken("token doesn't match")

    if token_expires < int(datetime.now().timestamp()):
        raise TokenExpired("token expired")

def root_password_auth(password) -> None or Exception:
    '''returns on success, exception on failure'''

    sql = '''select phash
             from users u
             where id=%s'''

    phash, = get_db().fetchone(sql, ROOT_UID)

    if not crypto.verify(password, phash):
        raise Exception("password doesn't match")

def password_auth(locid, telno, password) -> None or Exception:
    locid = locid.lower()
    if 'root' in (locid, telno):
        return root_password_auth(password)

    sql = '''select u.phash
             from users u left join beacon b
             on u.beacon = b.telno
             where b.locid=%s and u.telno=%s'''

    phash, = get_db().fetchone(sql, locid, telno)

    if not crypto.verify(password, phash):
        raise Exception("password doesn't match")

def root_password_set() -> bool:
    try:
        sql = '''select id
                 from users
                 where id=%s and phash is not null'''

        with get_db().cursor() as c:
            c.execute(sql, (ROOT_UID))
            return bool(c.rowcount)

    except Exception as e:
        print('root_password_set()', e) # DEBUG
        return False

def change_password(uid, password) -> None or Exception:
    sql = '''update users
             set phash=%s
             where id=%s'''

    updates = dict(phash = crypto.hash(password))
    wheres = dict(id = uid)
    if not get_db().update('users', updates, wheres):
        raise Exception("no such user")

def cookie_auth(allow_uids=all_of_them, allow_user_types=[UserType.ADMIN]) -> 'decorator':
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            locid = kwargs.get('locid', 'root')
            beacon_login = redirect(url_for('login', locid=locid))

            try:
                g.uid = int(request.cookies['u'])
                token = request.cookies['t']
            except ValueError:
                print("malformed cookies") #DEBUG
                return beacon_login
            except:
                print("couldn't get cookies") #DEBUG
                import traceback; traceback.print_exc() #DEBUG
                return beacon_login

            try:
                token_auth(g.uid, token)
            except TokenExpired:
                print("token expired") #DEBUG
                flash("Session expired, please log in again.")
                return beacon_login
            except BadToken:
                print("bad token") #DEBUG
                return beacon_login
            except NoSuchUser:
                print("no user with uid from cookie") #DEBUG
                return beacon_login
            except:
                print("couldn't authorize user") #DEBUG
                import traceback; traceback.print_exc() #DEBUG
                return beacon_login

            if g.uid not in allow_uids:
                print("user not allowed")
                return forbidden()

            if g.uid != ROOT_UID and user_locid(g.uid) != locid:
                print("logged-in user doesn't belong to this beacon")
                return beacon_login

            try:
                if user_type(g.uid) not in allow_user_types: #TODO combine user db calls
                    print("user type not allowed")
                    return forbidden()
            except:
                print("couldn't get type for user")
                import traceback; traceback.print_exc() #DEBUG
                return beacon_login

            return f(*args, **kwargs)

        return wrapped
    return wrapper

# APP SETUP

@app.context_processor
def beacon_name():
    return dict(
        AlertType=AlertType,
        UserType=UserType,
        beacon_nickname=beacon_nickname,
        ROOT_UID=ROOT_UID)

# ROUTES

@app.route('/test')
def test():
    return 'OK'

## NO INTERACTION

@app.route('/<locid>/logout')
def logout(locid):
    response = redirect(url_for('login', locid=locid.lower()))
    response.set_cookie('t', '')
    return response

@app.route('/<locid>/login/<int:uid>/<token>')
@app.route('/root/login/<token>', defaults={'locid': 'root', 'uid': ROOT_UID})
def autologin(locid, uid, token):
    locid = locid.lower()
    try:
        token_auth(uid, token)
        print("successfully authenticated through URL") # DEBUG
        response = redirect(url_for('root') if uid == ROOT_UID else url_for('alerts', locid=locid))
        response.set_cookie('u', str(uid))
        response.set_cookie('t', replace_token(uid))
        return response
    except Exception as e:
        print('autologin()', e) # DEBUG
        print("URL auth failed") # DEBUG
        return redirect(url_for('login', locid=locid))

## ROOT-ONLY

@app.route('/root', methods=['GET', 'POST'])
@cookie_auth(allow_uids=[ROOT_UID])
def root():
    # TODO: merge with settings() route
    if request.method == 'GET':
        force_password_reset = not root_password_set()
        if force_password_reset:
            flash("Welcome! Please set the root password.", 'info')
        return render_template('root.html', force_password_reset=force_password_reset)

    password = request.form['password']
    change_password(ROOT_UID, password)
    return redirect(url_for('root'))

@app.route('/beacons')
@cookie_auth(allow_uids=[ROOT_UID])
def beacons():

    sql = '''select `nickname`, `locid`, `description`
             from `beacons`'''
    beacons = [ (nickname, locid.upper(), description, url_for('settings', locid=locid.lower()))
                for nickname, locid, description in get_db().fetchall(sql) ]
    return render_template('beacons.html', beacons=beacons)

## ROOT-ONLY

@app.route('/<locid>/login', methods=['GET', 'POST'])
def login(locid):
    locid = locid.lower()
    if request.method == 'GET':
        return render_template('login.html', locid=locid)
    try:
        password = request.form['password']

        if locid == 'root' in locid:
            root_password_auth(password)
            uid = ROOT_UID
            response = redirect(url_for('root'))

        else:
            telno = request.form['telno']
            password_auth(locid, telno, password)
            uid = user_uid(locid, telno)
            response = redirect(url_for('alerts', locid=locid))

        response.set_cookie('u', str(uid))
        response.set_cookie('t', replace_token(uid))
        return response
    except:
        return redirect(url_for('login', locid=locid))

@app.route('/<locid>/alerts')
@cookie_auth()
def alerts(locid):
    locid = locid.lower()

    try:
        sql = '''select a.text, a.alert_type, a.id
                 from beacons b inner join alerts a
                 on b.telno = a.beacon
                 where b.locid=%s'''

        # build a map from alert type to messages
        d = {}
        for text, atype, aid in get_db().fetchall(sql, locid):
            atype = AlertType(atype)
            msgs = d.get(atype, [])
            msgs.append((text, aid))
            d[atype] = msgs

        return render_template('alerts.html',
                locid=locid,
                alerts=d)
    except:
        import traceback; traceback.print_exc() #DEBUG
        return 'No alerts!'

@app.route('/<locid>/alert/<alert>', methods=['PUT'])
@cookie_auth()
def put_alert(locid, alert):
    locid = locid.lower()
    action = AlertType(int(request.form['status'].strip()))

    text, sender = alert_details(alert)

    if action == AlertType.REPORT_RELAYED:
        blast(text, locid, sender)
        flash("Report sent out.")

    elif action == AlertType.REPORT_REJECTED:
        flash("Report rejected.")

    now = int(datetime.now().timestamp())
    get_db().update('alerts', {'alert_type': action, 'acted': now}, {'id': alert})
    return 'OK'

@app.route('/<locid>/alerts/new', methods=['POST'])
@cookie_auth()
def new_alert(locid):
    locid = locid.lower()

    text = request.form['text'].strip()
    sender = user_telno(g.uid)

    # send immediately if the beacon is so configured
    autosend_delay = beacon_autosend_delay(locid)
    if autosend_delay == 0:
        blast(text, locid, sender)
        flash("Message sent!")

    # otherwise put it in the queue
    else:
        now = int(datetime.now().timestamp())
        last_id = get_db().insert_into('alerts',
                beacon=beacon_telno(locid),
                telno=sender,
                text=text,
                reported=now,
                alert_type=AlertType.REPORT_PENDING)
        flash("Message queued!")

    return redirect(url_for('alerts', locid=locid))

def blast(text, locid, sender):
    print("[DEBUG] The following message from {} would have blasted to the {} beacon:\n{}".format(sender, locid, text))
    return #TODO

@app.route('/p/<secret>')
def process(secret):
    '''Process queue and prune old messages. This should be called at regular intervals.'''

    if secret != config.processing_key:
        return forbidden()

    response = ''
    now = int(datetime.now().timestamp())

    # fire off messages that were put in the queue and timed out
    sql = '''select b.locid, a.text, a.telno, a.id
             from beacons b inner join alerts a
             on b.telno = a.beacon
             where b.autosend_delay is not null
             and b.autosend_delay > 0
             and a.alert_type = {}
             and a.reported + b.autosend_delay < {}
    '''.format(AlertType.REPORT_PENDING, now)

    stale = get_db().fetchall(sql)
    queue_msg = "[DEBUG] {} reports timed out and were sent".format(len(stale))

    for locid, text, sender, alert in stale:
        get_db().update('alerts', {'alert_type': AlertType.REPORT_RELAYED, 'acted': now}, {'id': alert})
        blast(text, locid, sender)

    now = int(datetime.now().timestamp())
    prunable = [AlertType.REPORT_RELAYED, AlertType.REPORT_REJECTED, AlertType.WALLOPS_RELAYED]
    alert_types = tuple(int(at) for at in prunable)

    # delete all messages that have long since been acted upon
    sql = '''delete a
             from beacons b inner join alerts a
             on b.telno = a.beacon
             where b.prune_delay is not null
             and b.prune_delay > 0
             and a.acted is not null
             and a.alert_type in {}
             and a.acted + b.prune_delay < {}
    '''.format(alert_types, now)

    pruned = get_db().execute(sql)
    prune_msg = "[DEBUG] {} old reports were pruned".format(pruned)

    return "<p>" + "<br />".join([queue_msg, prune_msg]) + "</p>"

@app.route('/beacons/new', methods=['GET', 'POST'])
@cookie_auth(allow_uids=[ROOT_UID])
def new_beacon():

    # create form from defaults on GET or from request.form data on POST
    form = forms.Beacon()

    # if this is a POST request and the form validates ok
    if form.validate_on_submit():
        m = form.into_db()

        # store the new beacon in the database and show an edit form
        try:
            get_db().insert_into('beacons', **m)
            flash("Beacon created", 'info')
            flash(request.url_root.rstrip('/') + url_for('sms', locid=m['locid'], secret=m['secret']), 'new_secret')
            return redirect(url_for('settings', locid=m['locid']))
        except:
            flash("Couldn't create beacon")
            import traceback; traceback.print_exc() #DEBUG
            pass

    # if validation failed, inform the user
    for field, errors in form.errors.items():
        for error in errors:
            flash("{} {}".format(getattr(form, field).label.text, error), 'validation')

    # if this is a GET or failed POST, try again
    return render_template('beacon_form.html',
            verb='Create',
            form=form,
            post_to=url_for('new_beacon'))

@app.route('/<locid>/settings', methods=['GET', 'POST'])
@cookie_auth()
def settings(locid):
    # TODO what happens if the url is /root/settings?

    # on GET, populate the blank form with current settings
    if request.method == 'GET':
        try:
            m = get_db().get_from('beacons', forms.Beacon().into_db().keys(), 'locid = %s', (locid))
            form = forms.Beacon.from_db(m)
        except:
            import traceback; traceback.print_exc() #DEBUG
            return not_found()

    # on POST, populate the form with request.form data
    else:
        form = forms.Beacon()
        form.locid.data = locid

    form.locid.data = locid
    if form.validate_on_submit():
        m = form.into_db()

        try:
            get_db().update('beacons', updates=m, wheres={'telno': m['telno']})
            flash('Beacon updated', 'info')
            if form.new_secret.data:
                flash(request.url_root.rstrip('/') + url_for('sms', locid=m['locid'], secret=m['secret']), 'new_secret')
            return redirect(url_for('settings', locid=m['locid']))

        except Exception as e:
            flash("server error :(", 'error')
            import traceback; print("SERVER ERROR:", e, traceback.format_exc(), sep='\n', end='\n\n') #DEBUG
            pass

    # if validation failed, inform the user
    for field, errors in form.errors.items():
        for error in errors:
            flash("{} {}".format(getattr(form, field).label.text, error), 'validation')

    return render_template('beacon_form.html',
            locid=locid,
            verb='Edit',
            form=form,
            post_to=url_for('settings', locid=locid))

@app.route('/<locid>/sms/<secret>')
def sms(locid, secret):
    return render_template('todo.html', locid=locid) # TODO

@app.route('/<locid>/subscribers')
def subscribers(locid):
    users = users_of_type(locid, UserType.SUBSCRIBED)
    return render_template('users.html', users=users, title="Subscribers", locid=locid)

@app.route('/<locid>/admins')
def admins(locid):
    users = users_of_type(locid, UserType.ADMIN)
    return render_template('users.html', users=users, title="Admins", locid=locid)

@app.route('/<locid>/admins/new')
def new_admin(locid):
    form = forms.User()

    # if it's a POST request and the form validates correctly
    if form.validate_on_submit():

        # check if user exists
        try:
            user_uid(locid, form.telno.data)
            flash("There's already a user with that phone number!")
            return redirect(url_for('admins', locid=locid))
        except:
            pass

        try:
            now = int(datetime.now().timestamp())
            get_db().insert_into('users',
                    beacon=beacon_telno(locid),
                    telno=form.telno.data,
                    nickname='' if form.nickname.data is not None else form.nickname.data,
                    user_type=UserType.ADMIN,
                    phash=crypto.hash(password),
                    created=now)
            flash("User created")
        except:
            flash("Couldn't create user")


    # if validation failed, inform the user
    for field, errors in form.errors.items():
        for error in errors:
            flash("{} {}".format(getattr(form, field).label.text, error), 'validation')

    return redirect(url_for('admins', locid=locid))

@app.route('/<locid>/bans')
def bans(locid):
    users = users_of_type(locid, UserType.BANNED_WASNT_SUBSCRIBED, UserType.BANNED_WAS_SUBSCRIBED)
    return render_template('users.html', users=users, title="Banned numbers", locid=locid)

if __name__ == '__main__':
    app.run(port=config.port, debug=True)
