#!/usr/bin/env python3

import settings as config
import forms
from utils import random_token, all_of_them, IntEnum, call_some

from datetime import datetime
from functools import wraps
from collections import Counter
import pymysql

from passlib.context import CryptContext
crypto = CryptContext(schemes=['pbkdf2_sha256'])

#import plivo
#p = plivo.RestAPI(config.plivo_id, config.plivo_token)

# BACKEND SETUP

from flask import Flask, request, render_template, g, url_for, redirect, \
    make_response, get_flashed_messages, flash
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.secret_key = config.flask_secret_key
csrfp = CSRFProtect(app)

def get_db():
    if not hasattr(g, 'db'):
        g.db = pymysql.connect(**config.database)
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# DB ENUMS

class Role(IntEnum):
    NOT_SUBSCRIBED = 0
    SUBSCRIBED = 1
    ADMIN = 2
    BANNED_WASNT_SUBSCRIBED = 3
    BANNED_WAS_SUBSCRIBED = 4

class AlertType(IntEnum):
   REPORT_PENDING = 0
   REPORT_RELAYED = 1
   REPORT_REJECTED = 2
   WALLOPS_RELAYED = 3

# HELPERS

ROOT_UID = 1

def bad_request():
    return make_response(('Bad request :(', 400, {}))

def unauthorized():
    return make_response(('Unauthorized :(', 401, {}))

def forbidden():
    return make_response(('Forbidden :(', 403, {}))

def not_found():
    return make_response(('Not Found :(', 404, {}))

def insert_into(table, **kwargs):
    keys, values = zip(*kwargs.items())

    # get string representation, but leave None alone
    values = [ call_some(v, str) for v in values ]

    params = ', '.join(['%s'] * len(keys))
    columns = ', '.join('`{}`'.format(k) for k in keys)

    with get_db().cursor() as c:
        c.execute('insert into `{}` ({}) values ({})'.format(table, columns, params), values)
    get_db().commit()

def update(table, **kwargs):
    keys, values = zip(*kwargs.items())

    # get string representation, but leave None alone
    values = list(map(lambda v: call_some(v, str), values))

    updates = ', '.join( '`{}` = %s'.format(k) for k in keys )

    with get_db().cursor() as c:
        c.execute('update `{}` set {}'.format(table, updates), values)
    get_db().commit()

def get_from(table, fields, where_clause, params=()):
    columns = ', '.join( '`{}`'.format(field) for field in fields )
    sql = 'select {} from `{}` where {}'.format(columns, table, where_clause)

    with get_db().cursor() as c:
        c.execute(sql, params)
        result = c.fetchone()
        if result is None:
            raise Exception('not found')
        return dict(zip(fields, result))

def user_token_lifetime(uid):
    sql = '''select b.token_lifetime
             from beacon b inner join users u
             on b.telno = u.beacon
             where u.id=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return c.fetchone()[0]

def user_locid(uid) -> 'locid' or Exception:
    if uid == ROOT_UID:
        return 'root'

    sql = '''select b.locid
             from users u inner join beacon b
             where u.uid=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return c.fetchone()[0].lower()

def user_uid(locid, telno) -> 'uid' or Exception:
    locid = locid.lower()
    if 'root' in (locid, telno):
        return ROOT_UID

    sql = '''select u.uid
             from users u inner join beacon b
             on u.beacon = b.telno
             where b.locid=%s and u.telno=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (locid, telno))
        return c.fetchone()[0]

def user_telno(uid) -> 'telno' or Exception:
    if uid == ROOT_UID:
        return 'root'

    sql = '''select telno
             from users u
             where id=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return c.fetchone()[0]

def user_role(uid) -> Role or Exception:
    if uid == ROOT_UID:
        return Role.ADMIN

    sql = '''select role
             from users u
             where id=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return Role(c.fetchone()[0])

def beacon_nickname(locid) -> str:
    sql = '''select nickname
             from beacons
             where locid = %s'''

    try:
        with get_db().cursor() as c:
            c.execute(sql, (locid))
            return c.fetchone()[0]
    except:
        return ''

def replace_token(uid) -> 'token':
    if uid == ROOT_UID:
        token_lifetime = config.root_token_lifetime
    else:
        token_lifetime = user_token_lifetime()

    token = random_token()

    sql = '''update users
             set thash = %s, token_expires = %s
             where id=%s'''
    with get_db().cursor() as c:
        c.execute(sql, (crypto.hash(token), int(datetime.now().timestamp()) + token_lifetime, uid))
    get_db().commit()

    return token

def token_auth(uid, token) -> None or Exception:
    sql = '''select thash, token_expires
             from users
             where id=%s'''

    try:
        with get_db().cursor() as c:
            c.execute(sql, (uid))
            thash, token_expires = c.fetchone()
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

    with get_db().cursor() as c:
        c.execute(sql, (ROOT_UID))
        phash, = c.fetchone()

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

    with get_db().cursor() as c:
        c.execute(sql, (locid, telno))
        phash, = c.fetchone()

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

    except:
        return False

def change_password(uid, password) -> None or Exception:
    sql = '''update users
             set phash=%s
             where id=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (crypto.hash(password), uid))
        get_db().commit()
        if not c.rowcount:
            raise Exception("no such user")

def cookie_auth(allow_uids=all_of_them, allow_roles=[Role.ADMIN]) -> 'decorator':
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
                g.role = user_role(g.uid) # TODO: combine
                if g.role not in allow_roles:
                    print("role not allowed")
                    return beacon_login
            except:
                print("couldn't get role for user")
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
        Role=Role,
        beacon_nickname=beacon_nickname,
        ROOT_UID=ROOT_UID)

@app.cli.command()
def initdb():
    root_token = random_token()
    now = int(datetime.now().timestamp())
    insert_into('users',
        telno='root',
        beacon='root',
        role=Role.ADMIN,
        thash=crypto.hash(root_token),
        token_expires= now + config.root_token_lifetime,
        created=now)
    print("Run the app with ./app.py, then set the root password at http://localhost:5000/root/login/" + root_token)

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
    except:
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
    with get_db().cursor() as c:
        c.execute('select `nickname`, `locid`, `description` from `beacons`')
        beacons = [ (nickname, locid.upper(), description, url_for('settings', locid=locid.lower()))
                    for nickname, locid, description in c.fetchall() ]
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
        with get_db().cursor() as c:
            sql = '''select a.alert_type
                     from beacons b inner join alerts a
                     on b.telno = a.beacon
                     where b.locid=%s'''

            c.execute(sql, (locid))
            alerts = [ alert for alert, in c.fetchall() ]
            stats = Counter(AlertType(alert) for alert in alerts)
            return render_template('alerts.html',
                    locid=locid,
                    alerts=alerts,
                    stats=stats)
    except:
        import traceback; traceback.print_exc() #DEBUG
        return 'No alerts!'


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
            insert_into('beacons', **m)
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
            m = get_from('beacons', forms.Beacon().into_db().keys(), 'locid = %s', (locid))
            form = forms.Beacon.from_db(m)
        except:
            import traceback; traceback.print_exc() #DEBUG
            return not_found()

    # on POST, populate the form with request.form data
    else:
        form = forms.Beacon()

    if form.validate_on_submit():
        m = form.into_db()

        try:
            update('beacons', **m)
            flash('Beacon updated', 'info')
            if form.new_secret.data:
                flash(request.url_root.rstrip('/') + url_for('sms', locid=m['locid'], secret=m['secret']), 'new_secret')
            return redirect(url_for('settings', locid=m['locid']))

        except:
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
    return render_template('todo.html', locid=locid) # TODO

@app.route('/<locid>/admins')
def admins(locid):
    return render_template('todo.html', locid=locid) # TODO

@app.route('/<locid>/bans')
def bans(locid):
    return render_template('todo.html', locid=locid) # TODO

if __name__ == '__main__':
    app.run(port=5000, debug=True)
