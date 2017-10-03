#!/usr/bin/env python3
'''Flask webapp for smsbeacon'''

# internal

import config
import forms
from db import Database, UserType, AlertType, ROOT_UID
import utils
import responses

# stdlib

from datetime import datetime
from functools import wraps
from collections import Counter

# external

import os, sys; sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./vendored"))

import pymysql
import requests

from passlib.context import CryptContext
crypto = CryptContext(schemes=['pbkdf2_sha256'])

from flask import Flask, request, render_template, g, url_for, redirect, \
    make_response, get_flashed_messages, flash
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
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

def replace_token(uid, expires=True) -> 'token':
    token = utils.random_token()

    wheres = dict(id = uid)
    updates = dict(thash=crypto.hash(token))

    if uid == ROOT_UID:
        token_lifetime = config.root_token_lifetime
    else:
        token_lifetime = get_db().user_token_lifetime(uid)

    updates['token_expires'] = int(datetime.now().timestamp()) + token_lifetime

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

    try:
        thash, token_expires = get_db().get_token(uid)
    except:
        raise Exception("couldn't get user")

    if not crypto.verify(token, thash):
        raise BadToken("token doesn't match")

    if token_expires is not None and token_expires < int(datetime.now().timestamp()):
        raise TokenExpired("token expired")

def root_password_auth(password) -> None or Exception:
    '''returns on success, exception on failure'''

    sql = '''select phash
             from users u
             where id=%s'''

    # TODO: root can log into nonexistent beacons; no actions do anything, but web UI still allows it

    phash, = get_db().fetchone(sql, ROOT_UID)

    if not crypto.verify(password, phash):
        raise Exception("password doesn't match")

def password_auth(locid, telno, password) -> None or Exception:
    locid = locid.lower()
    if 'root' in (locid, telno):
        return root_password_auth(password)

    sql = '''select u.phash
             from users u left join beacons b
             on u.beacon = b.telno
             where b.locid=%s and u.telno=%s'''

    phash, = get_db().fetchone(sql, locid, telno)

    if not crypto.verify(password, phash):
        raise Exception("password doesn't match")

def change_password(uid, password) -> None or Exception:
    sql = '''update users
             set phash=%s
             where id=%s'''

    updates = dict(phash = crypto.hash(password))
    wheres = dict(id = uid)
    if not get_db().update('users', updates, wheres):
        raise Exception("no such user")

def cookie_auth(allow_uids=utils.all_of_them, allow_user_types=[UserType.ADMIN]) -> 'decorator':
    '''Attempts to authenticate a user based on 'u' and 't' cookies we
    previously set. On success, the authenticated user's information is stored
    as a dict in g.auth with the following structure:

    g.auth = {
        'uid': int,
        'user_type': UserType,
    }
    '''

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            locid = kwargs.get('locid', 'root')
            # TODO: redirect to requested page after successful login
            beacon_login = redirect(url_for('login', locid=locid))

            try:
                uid = int(request.cookies['u'])
                token = request.cookies['t']

            # malformed cookies
            except ValueError:
                return beacon_login

            # user without cookies tried to log in
            except:
                return beacon_login

            try:
                token_auth(uid, token)
            except TokenExpired:
                flash("Session expired, please log in again.")
                return beacon_login
            except BadToken:
                print("user {} tried to use incorrect token cookie {} to log in".format(uid, token))
                return beacon_login
            except NoSuchUser:
                print("user with cookie set to nonexistent user ID tried to log in")
                return beacon_login
            except:
                print("token_auth({}, {}): login failure".format(repr(uid), repr(token)))
                import traceback; traceback.print_exc() #DEBUG
                return beacon_login

            if uid not in allow_uids:
                m = "user {} tried to access {} but was disallowed because only these uids can access it: {}"
                print(m.format(uid, request.url, ', '.join(str(u) for u in allow_uids)))
                return beacon_login

            # is a user of this beacon?
            #TODO restructure auth so that this is implicit
            if uid != ROOT_UID and get_db().user_locid(uid) != locid:
                m = "user {} tried to access {} but was disallowed because they're not in that beacon"
                print(m.format(uid, request.url))
                return beacon_login

            try:
                #TODO combine user db calls
                ut = get_db().user_type(uid)
                if ut not in allow_user_types:
                    m = "user {} tried to access {} but was disallowed because only these user types can access it: {}"
                    print(m.format(uid, request.url, ', '.join(u.name.lower().replace('_', ' ') for u in allow_user_types)))
                    return beacon_login
            except:
                print("couldn't get type for user {}".format(uid))
                import traceback; traceback.print_exc() #DEBUG
                return beacon_login

            g.auth = dict(uid=uid, user_type=ut)
            return f(*args, **kwargs)

        return wrapped
    return wrapper

def raw_send_sms(plivo_id: str, plivo_token: str, src: str, dst: str, text: str, log=False, callback_url=None):
    url = "https://api.plivo.com/v1/Account/{}/Message/".format(plivo_id)
    req = dict(src=src, dst=dst, text=text)

    if callback_url:
        req['url'] = callback_url

    if not log:
        req['log'] = False

    print("[DEBUG]", req)
    requests.post(url, auth=(plivo_id, plivo_token), json=req).raise_for_status()

def send_sms(text, to, locid, url_root) -> 'smsid':
    # TODO: combine DB calls
    plivo_id, plivo_token = get_db().get_api_keys(locid)

    if isinstance(to, str):
        to = [to]
    to = '<'.join(utils.normal_telno(t) for t in to if t != 'root')

    print("[DEBUG] Beacon at {} sending SMS to {} via API call: \"{}\"".format(locid, to if to else "nobody", text))

    # plivo shits the bed if we send responses with no destination numbers
    if not to:
        return

    now = int(datetime.now().timestamp())

    # TODO: combine DB calls
    src = get_db().beacon_telno(locid)
    secret = utils.random_token(config.plivo_url_secret_length)
    smsid = get_db().insert_into('sms',
        src=src,
        dst=to,
        text=text,
        first_sent_at=now,
        last_sent_at=now,
        secret=secret)

    return raw_send_sms(plivo_id, plivo_token, src, to, text,

        # only log in debug mode
        log=app.debug,

        # allow plivo to tell us whether the message was delivered, so we can resend if it wasn't
        callback_url=url_root.rstrip('/') + url_for('sms_callback', smsid=smsid, secret=secret))

def resend_sms(smsid, error, log, url_root):
    secret = utils.random_token(config.plivo_url_secret_length)
    now = int(datetime.now().timestamp())
    try:
        get_db().execute('''
            update sms set
            last_sent_at = %s
            num_attempts = num_attempts + 1,
            errors = concat(errors, ',', %s),
            secret = %s
            where id = %s
        ''', now, str(error), secret, smsid)
    except Exception as e:
        print("[DEBUG] Couldn't update information on sms, so resend was aborted: ", e)
        raise e

    try:
        plivo_id, plivo_token, src, dst, text, num_attempts, errors = \
            get_db().fetchone('''
                select b.plivo_id, b.plivo_token, s.src, s.dst, s.text, s.num_attempts, s.errors
                from sms s inner join beacons b
                on s.src = b.telno
                where s.id = %s''', smsid)

    except Exception as e:
        print("[DEBUG] Couldn't get information to resend SMS:", e)
        raise e

    if num_attempts < config.send_attempts:
        raw_send_sms(plivo_id, plivo_token, src, dst, text, log=log,
            callback_url=url_root.rstrip('/') + url_for('sms_callback', smsid=smsid, secret=secret))
        print("[DEBUG] Resent message from {} to {}: \"{}\"".format(src, dst, text))
    else:
        print("[DEBUG] Send failed with errors {} after {} attempts.".format(errors, num_attempts))
        print("        Message was from {} to {}: \"{}\"".format(src, dst, text))

def delete_sms(smsid):
    return get_db().execute('delete from sms where id = %s', smsid)

def blast(text, locid, user_types, url_root, exclude=[]):
    if isinstance(exclude, str):
        exclude = [exclude]

    # TODO: combine DB calls
    to = get_db().users_of_type(locid, *user_types).keys()
    if exclude:
        to = [ t for t in to if t not in exclude ]
    return send_sms(text, to, locid, url_root)

def inform_admins_new(text, aid, locid, url_root, exclude=[]):
    '''exclude is a telno or a list of telno'''

    if isinstance(exclude, str):
        exclude = [exclude]

    m = "New submission to the {} beacon: \"{}\"\nApprove or reject at {}"
    for telno, (uid, _, _, _, _) in get_db().users_of_type(locid, UserType.ADMIN).items():

        if telno in exclude:
            continue

        # TODO: on autologin, go directly to relevant alert id and highlight
        autologin_url = request.url_root.rstrip('/') + url_for('autologin', locid=locid, uid=uid, token=replace_token(uid))
        send_sms(m.format(locid.upper(), text, autologin_url), telno, locid, url_root)

    print("[DEBUG] Admins informed")

def inform_admins_responded(how: AlertType, text, aid, by_whom: 'nickname', locid, url_root, exclude=[]):
    '''exclude is telno or a list of telno'''

    if isinstance(exclude, str):
        exclude = [exclude]

    if how == AlertType.REPORT_RELAYED and by_whom is None:
        msg = "Automatically blasting out message that nobody responded to: \"{}\"".format(text)
    else:
        if how == AlertType.REPORT_RELAYED:
            verb = 'approved'
            clause = " which is now being relayed"
        elif how == AlertType.REPORT_REJECTED:
            verb = 'rejected'
            clause = ''
        else:
            verb = 'modified'
            clause = " to the \"{}\" state".format(how.name.lower().replace('_', ' '))

        msg = "{} {} a message{}: \"{}\"".format(by_whom, verb, clause, text)

    blast(msg, locid, [UserType.ADMIN], url_root, exclude=exclude)

# APP SETUP

@app.context_processor
def template_context():
    '''Makes additional objects available to all templates without having to
    pass them into each.'''
    return dict(
        AlertType=AlertType,
        UserType=UserType,
        beacon_nickname=get_db().beacon_nickname,
        ROOT_UID=ROOT_UID)

# ROUTES

@app.route('/test')
def test():
    return 'OK'

## NO INTERACTION

@app.route('/')
def landing():
    return app.send_static_file('landing.html')

@app.route('/<locid>/logout')
def logout(locid):
    response = redirect(url_for('login', locid=locid.lower()))
    response.set_cookie('t', '')
    return response

@app.route('/<locid>/login/<int:uid>/<token>')
@app.route('/root/login/<token>', defaults={'locid': 'root', 'uid': ROOT_UID})
def autologin(locid, uid, token):
    # TODO: on autologin, go directly to relevant alert id and highlight
    locid = locid.lower()
    try:
        token_auth(uid, token)
        print("successfully authenticated through URL") # DEBUG

        if not get_db().password_set(uid):
            response = redirect(url_for('first_login', locid=locid))
            response.set_cookie('t', token)
        else:
            response = redirect(url_for('root') if uid == ROOT_UID else url_for('alerts', locid=locid))
            # TODO: perhaps we shouldn't replace the token, just set it to expire if it's an indefinite token
            response.set_cookie('t', replace_token(uid))

        response.set_cookie('u', str(uid))
        return response

    except Exception as e:
        print('autologin()', e) # DEBUG
        print("URL auth failed") # DEBUG
        return redirect(url_for('login', locid=locid))

## ROOT-ONLY

@app.route('/root')
@cookie_auth(allow_uids=[ROOT_UID])
def root():
    # TODO: merge with settings() route
    return render_template('root.html', locid='root', title_override="root settings")

@app.route('/beacons')
@cookie_auth(allow_uids=[ROOT_UID])
def beacons():

    sql = '''select `nickname`, `locid`, `description`
             from `beacons`'''
    beacons = [ (nickname, locid.lower(), description)
                for nickname, locid, description in get_db().fetchall(sql) ]
    return render_template('beacons.html', beacons=beacons)

## LOGGING IN

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
            telno = request.form['telno'].strip()
            if telno != 'root':
                telno = utils.normal_telno(telno)
            password_auth(locid, telno, password)
            uid = get_db().user_uid(locid, telno)
            response = redirect(url_for('alerts', locid=locid))

        response.set_cookie('u', str(uid))
        response.set_cookie('t', replace_token(uid))
        return response
    except:
        import traceback; traceback.print_exc() #DEBUG
        return redirect(url_for('login', locid=locid))

@app.route('/<locid>/first-login')
@cookie_auth()
def first_login(locid):
    return render_template('first_login.html', locid=locid)

@app.route('/<locid>')
def locid_root(locid):
    return redirect(url_for('alerts', locid=locid))

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

@app.route('/<locid>/alerts/new', methods=['POST'])
@cookie_auth()
# TODO: should be called post_alert
def new_alert(locid):
    locid = locid.lower()
    text = request.form['text'].strip()

    # TODO: combine DB queries
    sender = get_db().user_telno(g.auth['uid'])
    beacon = get_db().beacon_telno(locid)

    # send immediately if the beacon is so configured
    autosend_delay = get_db().beacon_autosend_delay(locid)
    if autosend_delay == 0:
        now = int(datetime.now().timestamp())
        get_db().insert_into('alerts',
                beacon=beacon,
                telno=sender,
                text=text,
                reported_by=sender,
                reported_at=now,
                acted_by=sender,
                acted_at=now,
                alert_type=AlertType.REPORT_RELAYED)

        blast(text, locid, [UserType.SUBSCRIBED], request.url_root)

        nickname, = get_db().fetchone('''
            select nickname
            from users
            where beacon = %s
            and telno = %s
        ''', beacon, sender)
        if nickname is None:
            nickname = "at {}".format(sender)

        blast("Admin {} just sent alert out: \"{}\"".format(nickname, text), locid, [UserType.ADMIN], request.url_root, exclude=sender)
        flash("Message sent out, thanks.")

    # otherwise put it in the queue
    else:
        now = int(datetime.now().timestamp())
        aid = get_db().insert_into('alerts',
                beacon=beacon,
                telno=sender,
                text=text,
                reported_at=now,
                reported_by=sender,
                alert_type=AlertType.REPORT_PENDING)
        inform_admins_new(text, aid, locid, request.url_root, exclude=sender)
        flash("Message queued and other admins notified.")

    return redirect(url_for('alerts', locid=locid))

@app.route('/<locid>/alert/<int:alert>', methods=['PATCH'])
@cookie_auth()
def patch_alert(locid, alert):
    locid = locid.lower()
    new_alert_type = AlertType(int(request.form['alert_type'].strip()))

    text, sender = get_db().alert_details(alert)

    admin_telno, nickname = get_db().fetchone('select telno, nickname from users where id = %s', g.auth['uid'])
    if nickname is None:
        nickname = admin_telno

    get_db().change_alert_type(alert, new_alert_type, g.auth['uid'])

    if new_alert_type == AlertType.REPORT_RELAYED:
        blast(text, locid, [UserType.SUBSCRIBED], request.url_root, exclude=sender)
        send_sms("Your report was sent out, thanks for submitting.", sender, locid, request.url_root)
        flash("Report sent out.")

    elif new_alert_type == AlertType.REPORT_REJECTED:
        flash("Report rejected.")

    inform_admins_responded(new_alert_type, text, alert, nickname, locid, request.url_root, exclude=admin_telno)

    return 'OK'

@app.route('/c/<int:smsid>/<secret>', methods=['POST'])
def sms_callback(smsid, secret):
    BLOCKED = 200

    try:
        real_secret, = get_db().fetchone('''
            select secret
            from sms
            where id = %s
        ''', smsid)
    except:
        print("[DEBUG] In SMS callback, SMS with id {} not found".format(smsid))
        return not_found()

    if secret != real_secret:
        print("[DEBUG] SMS callback secret didn't match id {}".format(smsid))
        return forbidden()

    error_code = request.values.get(['ErrorCode'], None)
    if error_code is None:
        delete_sms(smsid)
        return 'OK'

    error_code = int(error_code)

    if error_code == BLOCKED:
        try:
            delete_sms(smsid)
        except Exception as e:
            print("[DEBUG] couldn't delete blocked sms")
        try:
            get_db().fetchone('''
                update u
                set u.user_type = %s
                from users u inner join sms s
                on u.telno = s.to
                where s.id = %s
            ''', UserType.NOT_SUBSCRIBED, smsid)
        except Exception as e:
            print("[DEBUG] couldn't update blocked user")

    elif error_code in config.resend_on_errors:
        resend_sms(smsid, error_code, app.debug, request.url_root)

@app.route('/p/<secret>')
def process(secret):
    '''Process queue and prune old messages. This should be called at regular intervals.'''

    if secret != config.processing_key:
        return forbidden()

    now = int(datetime.now().timestamp())

    # fire off messages that were put in the queue and timed out
    sql = '''select b.locid, a.text, a.telno, a.id
             from beacons b inner join alerts a
             on b.telno = a.beacon
             where b.autosend_delay is not null
             and b.autosend_delay > 0
             and a.alert_type = {}
             and a.reported_at + b.autosend_delay < {}
    '''.format(AlertType.REPORT_PENDING, now)

    stale = get_db().fetchall(sql)
    print("[DEBUG] {} reports timed out and were sent".format(len(stale)))

    for locid, text, sender, alert in stale:
        get_db().update('alerts', {'alert_type': AlertType.REPORT_RELAYED, 'acted_at': now}, {'id': alert})
        blast(text, locid, [UserType.SUBSCRIBED], request.url_root, exclude=sender)
        inform_admins_responded(AlertType.REPORT_RELAYED, text, None, locid, request.url_root)
        send_sms("Your report was sent out, thanks for submitting.", sender, locid, request.url_root)

    now = int(datetime.now().timestamp())
    prunable = [AlertType.REPORT_RELAYED, AlertType.REPORT_REJECTED, AlertType.WALLOPS_RELAYED]

    # delete all messages that have long since been acted upon
    sql = '''delete a
             from beacons b inner join alerts a
             on b.telno = a.beacon
             where b.prune_delay is not null
             and a.acted_at is not null
             and b.prune_delay > 0
             and a.alert_type in ({})
             and a.acted_at + b.prune_delay < {}
    '''.format(','.join(str(at) for at in prunable), now)

    pruned = get_db().execute(sql)
    print("[DEBUG] {} old reports were pruned".format(pruned))

    return "OK"

@app.route('/<locid>/sms/<secret>', methods=['GET', 'POST'])
@csrfp.exempt
def incoming_sms(locid, secret):
    print("[DEBUG] sms sent to", locid)
    try:
        actual_secret, = get_db().fetchone('select secret from beacons where locid = %s', locid)
    except Exception as e:
        print("[DEBUG] couldn't get this beacon's secret:", e)
        return bad_request()

    if secret != actual_secret:
        print("[DEBUG] secret was wrong")
        return bad_request()

    try:
        sender = utils.normal_telno(request.values['From'].strip())
        beacon = utils.normal_telno(request.values['To'].strip())
        text = request.values['Text'].strip()
    except TypeError:
        print("[DEBUG] incoming sms was malformed")
        return bad_request()

    try:
        user_type = get_db().user_type_by_telno(sender)
    except Exception as e:
        print("[DEBUG]", e)
        import traceback; traceback.print_exc() #DEBUG
        user_type = UserType.NOT_SUBSCRIBED

    print("[DEBUG] from {} ({}):".format(sender, user_type.name.lower().replace('_', ' ')))
    print('[DEBUG]   "{}"'.format(text))

    if user_type in (UserType.BANNED_WASNT_SUBSCRIBED, UserType.BANNED_WAS_SUBSCRIBED):
        return 'OK'

    if 'subscribe' in text.lower().split() or text.lower() in ['start', 'yes', 'resume', 'resume all', 'unstop', 'go']:
        if user_type == UserType.NOT_SUBSCRIBED:
            get_db().subscribe(sender, beacon)
            return responses.now_subscribed(sender, beacon)
        else:
            return responses.already_subscribed(sender, beacon)

    elif text.lower() in ['stop', 'end', 'quit', 'cancel', 'unsubscribe', 'unsub', 'stop all']:
        get_db().unsubscribe(sender, beacon)
        return 'OK'

    elif user_type == UserType.ADMIN:
        if text == 'ping':
            return responses.pong(sender, beacon)

        now = int(datetime.now().timestamp())
        get_db().insert_into('alerts',
                beacon=beacon,
                telno=sender,
                text=text,
                reported_at=now,
                reported_by=sender,
                acted_at=now,
                acted_by=sender,
                alert_type=AlertType.REPORT_RELAYED)
        blast(text, locid, [UserType.SUBSCRIBED], request.url_root)

        nickname, = get_db().fetchone('''
            select nickname
            from users
            where beacon = %s
            and telno = %s
        ''', beacon, sender)
        if nickname is None:
            nickname = "at {}".format(sender)

        blast("Admin {} just sent alert out: \"{}\"".format(nickname, text), locid, [UserType.ADMIN], request.url_root, exclude=sender)
        return responses.blasted_thanks(sender, beacon)

    else:
        now = int(datetime.now().timestamp())
        aid = get_db().insert_into('alerts',
                beacon=beacon,
                telno=sender,
                text=text,
                reported_at=now,
                reported_by=sender,
                alert_type=AlertType.REPORT_PENDING)
        inform_admins_new(text, aid, locid, request.url_root, exclude=sender)
        return responses.submitted_thanks(sender, beacon)

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
            flash(request.url_root.rstrip('/') + url_for('incoming_sms', locid=m['locid'], secret=m['secret']), 'new_secret')
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
                flash(request.url_root.rstrip('/') + url_for('incoming_sms', locid=m['locid'], secret=m['secret']), 'new_secret')
            return redirect(url_for('settings', locid=m['locid']))

        except Exception as e:
            flash("server error :(", 'error')
            import traceback; print("[ERROR] ", e, traceback.format_exc(), sep='\n', end='\n\n') #DEBUG
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

@app.route('/<locid>/subscribers', endpoint='subscribers', defaults={'kind': 'Subscribers', 'user_types': [UserType.SUBSCRIBED]})
@app.route('/<locid>/admins', endpoint='admins', defaults={'kind': 'Admins', 'user_types': [UserType.ADMIN]})
@app.route('/<locid>/bans', endpoint='bans', defaults={'kind': 'Bans', 'user_types': [UserType.BANNED_WASNT_SUBSCRIBED, UserType.BANNED_WAS_SUBSCRIBED]})
@cookie_auth()
def users(locid, kind, user_types):
    '''The first user in the user_types array is used as the type of new users
    created from this page.'''
    users = get_db().users_of_type(locid, *user_types)
    return render_template('users.html', users=users, kind=kind, locid=locid, user_types=user_types)

@app.route('/<locid>/users/<int:uid>', methods=['PATCH'])
@cookie_auth()
def patch_user(locid, uid):
    locid = locid.lower()

    # if you're changing your password, you don't get to change anything else
    if 'password' in request.form:
        if uid != g.auth['uid']:
            return forbidden()

        try:
            change_password(uid, request.form['password'])
            flash("Password updated!")
            return 'OK'
        except:
            flash("Couldn't update password.")

    try:
        new_user_type = UserType(int(request.form['user_type'].strip()))
        updates = {'user_type': new_user_type}

        # TODO: gracefully enforce that all admins must have nicknames
        if new_user_type == UserType.ADMIN:
            updates['nickname'] = request.form['nickname'].strip()
            updates['phash'] = None

        # clear out the nickname for all normal users
        elif new_user_type in (UserType.SUBSCRIBED, UserType.NOT_SUBSCRIBED):
            updates['nickname'] = None

        # TODO: gracefully enforce that all banned users must have a ban_reason
        if new_user_type in (UserType.BANNED_WASNT_SUBSCRIBED, UserType.BANNED_WAS_SUBSCRIBED):
            updates['ban_reason'] = request.form['ban_reason'].strip()

        # clear out the ban_reason for unbanned users
        else:
            updates['ban_reason'] = None

        get_db().update('users', updates, {'id': uid})
        flash("User updated.")
    except:
        flash("Couldn't update user.")

    try:
        if new_user_type == UserType.ADMIN:
            token = replace_token(uid)
            url = url_for('autologin', uid=uid, locid=locid, token=token)
            send_sms("You're now an admin on the {} beacon. Click to log in: {}".format(locid, request.url_root.rstrip('/') + url),
                     get_db().user_telno(uid),
                     locid,
                     request.url_root)
            flash("Sent a text with a login link to the new admin")
    except Exception as e:
        print("[ERROR] Couldn't text the new admin their credentials:", e)
        flash("Couldn't text the new admin their credentials")

    return 'OK'

@app.route('/<locid>/users/new', methods=['POST'])
@cookie_auth()
def post_user(locid):
    locid = locid.lower()
    form = forms.User()

    if request.form.get('return_to', '').strip():
        back = redirect(request.form['return_to'].strip())
    else:
        back = redirect(url_for('alerts', locid=locid))

    # if it's a POST request and the form validates correctly
    if form.validate_on_submit():

        model = form.into_db()

        # if the user already exists in this beacon, delete and start over
        try:
            uid = get_db().user_uid(locid, model['telno'])
            if uid == g.auth['uid']:
                flash("Can't edit yourself!")
                return back
            try:
                get_db().delete_user(uid)
            except:
                flash("There's already a user with that phone number, and I can't delete them!")
                return back
        except:
            pass

        beacon = get_db().beacon_telno(locid)
        now=int(datetime.now().timestamp())

        model['created'] = now
        model['beacon'] = beacon

        try:
            uid = get_db().insert_into('users', **model)
            flash('Phone number registered')
        except:
            flash("Couldn't register number")
            return back

        if model['user_type'] == UserType.ADMIN:
            try:
                token = replace_token(uid)
                url = url_for('autologin', uid=uid, locid=locid, token=token)
                send_sms("You're now an admin on the {} beacon. Click to log in: {}".format(locid, request.url_root.rstrip('/') + url),
                         model['telno'], # normalized already by form
                         locid,
                         request.url_root)
                flash("Sent a text with a login link to the new admin")
            except Exception as e:
                print("[ERROR] Couldn't text the new admin their credentials:", e)
                flash("Couldn't text the new admin their credentials")
                return back

    # if validation failed, inform the user
    for field, errors in form.errors.items():
        for error in errors:
            flash("{} {}".format(getattr(form, field).label.text, error), 'validation')

    return back

@app.route('/<locid>/users/bulk-subscribe', methods=['GET', 'POST'])
@cookie_auth()
def bulk_subscribe(locid):
    locid = locid.lower()

    if request.method == 'GET':
        return render_template('bulk_subscribe.html', locid=locid)

    try:
        telnos = [ utils.normal_telno(telno) for telno in request.form['telnos'].strip().split() ]
    except Exception as e:
        import traceback; print("[ERROR] ", e, traceback.format_exc(), sep='\n', end='\n\n') #DEBUG
        return bad_request()

    beacon = get_db().beacon_telno(locid)

    #TODO make this a bulk insert
    for telno in telnos:
        get_db().insert_into('users',
            beacon=beacon,
            telno=telno,
            user_type=UserType.SUBSCRIBED,
            created=int(datetime.now().timestamp()))

    flash("{} subscribers added".format(len(telnos)))
    return redirect(url_for('subscribers', locid=locid))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.port, debug=(config.public_url == 'localhost'))
