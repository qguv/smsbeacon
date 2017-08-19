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

def user_token_lifetime(uid):
    sql = '''select b.token_lifetime
             from beacon b inner join users u
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

def token_auth(uid, token) -> None or Exception:
    sql = '''select thash, token_expires
             from users
             where id=%s'''

    try:
        thash, token_expires = get_db().fetchone(sql, uid)
    except:
        raise Exception("couldn't get user")

    if token_expires < int(datetime.now().timestamp()):
        raise Exception("token expired")

    if not crypto.verify(token, thash):
        raise Exception("token doesn't match")

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
            try:
                g.uid = int(request.cookies['u'])
                token = request.cookies['t']
            except KeyError:
                print("couldn't get cookies") #DEBUG
                return unauthorized()
            except ValueError:
                print("invalid uid") #DEBUG
                return unauthorized()

            # TODO: we should redirect to the login for the locid they
            # requested, not the one they ostensibly belong to, because one
            # user may have several accounts on separate beacons
            try:
                g.locid = user_locid(g.uid)
            except:
                print("couldn't get locid for user") #DEBUG
                return unauthorized()

            beacon_login = redirect(url_for('login', locid=g.locid))

            if g.uid not in allow_uids:
                print("uid not allowed")
                return beacon_login

            try:
                g.user_type = user_type(g.uid) # TODO: combine
                if g.user_type not in allow_user_types:
                    print("user type not allowed")
                    return beacon_login
            except:
                print("couldn't get type for user")
                return beacon_login

            try:
                token_auth(g.uid, token)
            except Exception as e:
                print("wrong token") #DEBUG
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
    if g.uid != ROOT_UID and g.locid != locid:
        return redirect(url_for('login', locid=locid))

    try:
        sql = '''select a.alert_type
                 from beacons b inner join alerts a
                 on b.telno = a.beacon
                 where b.locid=%s'''
        alerts = [ alert for alert, in get_db().fetchall(sql, locid) ]

        return render_template('alerts.html',
                locid=locid,
                alerts=alerts)
    except:
        import traceback; traceback.print_exc() #DEBUG
        return 'No alerts!'

@app.route('/<locid>/alerts/new', methods=['POST'])
@cookie_auth()
def new_alert(locid):
    locid = locid.lower()
    if g.uid != ROOT_UID and g.locid != locid:
        return redirect(url_for('login', locid=locid))

    return render_template('todo.html', locid=locid) # TODO post a new alert

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
    if g.uid != ROOT_UID and g.locid != locid:
        return forbidden()

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
        # TODO: shouldn't be allowed to change the locid by being sneaky

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

@app.route('/<locid>/bans')
def bans(locid):
    users = users_of_type(locid, UserType.BANNED_WASNT_SUBSCRIBED, UserType.BANNED_WAS_SUBSCRIBED)
    return render_template('users.html', users=users, title="Banned numbers", locid=locid)

if __name__ == '__main__':
    app.run(port=config.port, debug=True)
