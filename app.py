#!/usr/bin/env python3

import settings

from enum import IntEnum as _IntEnum
from threading import Thread
from datetime import datetime
from random import SystemRandom
from functools import wraps
import traceback #DEBUG
import string
import pymysql

from passlib.context import CryptContext
crypto = CryptContext(schemes=["pbkdf2_sha256"])

#import plivo
#p = plivo.RestAPI(settings.plivo_id, settings.plivo_token)

# BACKEND SETUP

from flask import Flask, request, render_template, g, url_for, redirect, make_response
app = Flask(__name__)

def get_db():
    if not hasattr(g, 'db'):
        g.db = pymysql.connect(**settings.database)
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# DB ENUMS

ROOT_UID = 1

class _AllOfThem():
    def __contains__(self, _):
        return True

all_of_them = _AllOfThem()

class IntEnum(_IntEnum):
    def __str__(self, *args, **kwargs):
        return str(int(self))

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

def unauthorized():
    return make_response(('Unauthorized :(', 401, {}))

def forbidden():
    return make_response(('Forbidden :(', 403, {}))

def not_found():
    return make_response(('Not Found :(', 404, {}))

def random_token(length=16) -> str:
    return ''.join(SystemRandom().choices(string.ascii_uppercase + string.digits, k=length))

def insert_into(cursor, table, **kwargs):
    kwargs = { k: str(v) for k, v in kwargs.items() }
    items = kwargs.items()
    keys, values = zip(*items)
    params = ", ".join(['%s'] * len(kwargs))
    columns = ", ".join('`{}`'.format(k) for k in keys)

    with get_db().cursor() as c:
        c.execute("insert into `{}` ({}) values ({})".format(table, columns, params), values)
    get_db().commit()

def user_token_lifetime(uid):
    sql = '''select b.token_lifetime
             from beacon b inner join users u
             on b.telno = u.beacon
             where u.id=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return c.fetchone()[0]

def user_locid(uid) -> "locid" or Exception:
    if uid == ROOT_UID:
        return "root"

    sql = '''select b.locid
             from users u inner join beacon b
             where u.uid=%s'''

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        return c.fetchone()[0].lower()

def user_uid(locid, telno) -> "uid" or Exception:
    locid = locid.lower()
    if 'root' in (locid, telno):
        return ROOT_UID

    sql = '''select u.uid
             from users u inner join beacon b
             on u.beacon = b.telno
             where b.locid=%s and u.telno=%s'''

    with get_db().cursor() as c:
        return c.execute(sql, (locid, telno)).findone()[0]

def user_telno(uid) -> "telno" or Exception:
    if uid == ROOT_UID:
        return 'root'

    sql = '''select telno
             from users u
             where id=%s'''

    with get_db().cursor() as c:
        return c.execute(sql, (uid)).findone()[0]

def user_role(uid) -> Role or Exception:
    if uid == ROOT_UID:
        return Role.ADMIN

    sql = '''select role
             from users u
             where id=%s'''

    with get_db().cursor() as c:
        return Role(c.execute(sql, (uid)).findone()[0])

def replace_token(uid) -> "token":
    if uid == ROOT_UID:
        token_lifetime = settings.root_token_lifetime
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

    with get_db().cursor() as c:
        c.execute(sql, (uid))
        thash, token_expires = c.fetchone()
    print("got user with uid", uid) #DEBUG

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

# CLI

@app.cli.command()
def initdb():
    root_token = random_token()
    now = int(datetime.now().timestamp())
    with get_db().cursor() as c:
        insert_into(c, "users",
            telno='root',
            beacon='root',
            role=Role.ADMIN,
            thash=crypto.hash(root_token),
            token_expires= now + settings.root_token_lifetime,
            created=now)
    get_db().commit()
    print("Run the app with ./app.py, then set the root password at http://localhost:5000/root/login/" + root_token)

# ROUTES

@app.route('/test')
def test():
    return 'OK'

@app.route('/<locid>/logout')
def logout(locid):
    response = redirect(url_for('login', locid=locid))
    response.set_cookie('t', '')
    return response

@app.route('/<locid>/login/<int:uid>/<token>')
@app.route('/root/login/<token>', defaults={'locid': 'root', 'uid': ROOT_UID})
def autologin(locid, uid, token):
    try:
        token_auth(uid, token)
        print("successfully authenticated through URL") # DEBUG
        response = redirect(url_for('root') if uid == ROOT_UID else url_for('alerts', locid=locid))
        response.set_cookie('u', str(uid))
        response.set_cookie('t', replace_token(uid))
        return response
    except:
        print("URL auth failed") # DEBUG
        print(traceback.format_exc()) #DEBUG
        return redirect(url_for('login', locid=locid))

@app.route('/<locid>/login', methods=['GET', 'POST'])
def login(locid):
    if request.method == 'GET':
        return render_template("login.html", locid=locid)
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
        print(traceback.format_exc()) #DEBUG
        return redirect(url_for('login', locid=locid))

@app.route('/root', methods=['GET', 'POST'])
@cookie_auth(allow_uids=[ROOT_UID])
def root():
    if request.method == 'GET':
        return render_template("root.html", force_password_reset=not root_password_set())

    password = request.form['password']
    change_password(ROOT_UID, password)
    return redirect(url_for('root'))

@app.route('/<locid>/alerts')
@cookie_auth()
def alerts(locid):
    if g.uid != ROOT_UID and g.locid != locid:
        return forbidden()

    sql = '''select b.nickname, b.description
             from beacons b left join alerts a
             on b.telno = a.beacon
             where b.locid=%s'''

    try:
        with get_db().cursor() as c:
            c.execute(sql, (locid))
            nickname, b.description = c.fetchone()
    except:
        return not_found()

    return render_template("alerts.html", count=c.rowcount, nickname=nickname, locid=locid)

@app.route('/beacons')
@cookie_auth(allow_uids=[ROOT_UID])
def beacons():
    return 'TODO' #TODO

@app.route('/beacons/new')
@cookie_auth(allow_uids=[ROOT_UID])
def new_beacon():
    return 'TODO' #TODO

if __name__ == "__main__":
    app.run(port=5000, debug=True)
