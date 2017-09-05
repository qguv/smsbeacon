'''Database support for smsbeacon'''

# internal

import config
import utils

# stdlib

from datetime import datetime

# external

import os, sys; sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./vendored"))

from pymysql import connect

ROOT_UID = 1

class UserType(utils.IntEnum):
    NOT_SUBSCRIBED = 0
    SUBSCRIBED = 1
    ADMIN = 2
    BANNED_WASNT_SUBSCRIBED = 3
    BANNED_WAS_SUBSCRIBED = 4

class AlertType(utils.IntEnum):
     REPORT_PENDING = 0
     REPORT_RELAYED = 1
     REPORT_REJECTED = 2
     WALLOPS_RELAYED = 3

class Database:

    def __init__(self):
        self.db = connect(**config.database)

    def close(self):
        return self.db.close()

    # =====================
    # generic query helpers
    # =====================

    def execute(self, sql, *values) -> 'rowcount':

        # get string representation, but leave None alone
        values = [ utils.maybe_call(str, v) for v in values ]

        with self.db.cursor() as c:
            c.execute(sql, values)
            self.db.commit()
            return c.rowcount

    def insert_into(self, table, **kwargs) -> 'new_id':
        keys, values = zip(*kwargs.items())

        # get string representation, but leave None alone
        values = [ utils.maybe_call(str, v) for v in values ]

        params = ', '.join(['%s'] * len(keys))
        columns = ', '.join('`{}`'.format(k) for k in keys)

        with self.db.cursor() as c:
            c.execute('insert into `{}` ({}) values ({})'.format(table, columns, params), values)
            last_id = c.lastrowid
        self.db.commit()
        return last_id

    def update(self, table, updates=dict(), wheres=dict()) -> 'rowcount':
        update_keys, update_values = zip(*updates.items())
        where_keys, where_values = zip(*wheres.items())

        # get string representation, but leave None alone
        update_values = [ utils.maybe_call(str, v) for v in update_values ]
        where_values = [ utils.maybe_call(str, v) for v in where_values ]

        updates = ', '.join( '`{}` = %s'.format(k) for k in update_keys )
        wheres = ' and '.join( '`{}` = %s'.format(k) for k in where_keys )

        with self.db.cursor() as c:
            c.execute('update `{}` set {} where {}'.format(table, updates, wheres), update_values + where_values)
            self.db.commit()
            return c.rowcount

    def get_from(self, table, fields, where_clause, params=()):
        columns = ', '.join( '`{}`'.format(field) for field in fields )
        sql = 'select {} from `{}` where {}'.format(columns, table, where_clause)

        with self.db.cursor() as c:
            c.execute(sql, params)
            result = c.fetchone()
            if result is None:
                raise Exception('not found')
            return dict(zip(fields, result))

    def fetchone(self, sql, *replacements):

        # get string representation, but leave None alone
        replacements = [ utils.maybe_call(str, r) for r in replacements ]

        with self.db.cursor() as c:
            c.execute(sql, replacements)
            return c.fetchone()

    def fetchall(self, sql, *replacements):

        # get string representation, but leave None alone
        replacements = [ utils.maybe_call(str, r) for r in replacements ]

        with self.db.cursor() as c:
            c.execute(sql, replacements)
            return c.fetchall()

    # ====================
    # custom query helpers
    # ====================

    def user_locid(self, uid) -> 'locid' or Exception:
        if uid == ROOT_UID:
            return 'root'

        sql = '''select b.locid
                 from users u inner join beacons b
                 where u.id = %s'''

        return self.fetchone(sql, uid)[0].lower()

    def user_uid(self, locid, telno) -> 'uid' or Exception:
        locid = locid.lower()
        if 'root' in (locid, telno):
            return ROOT_UID

        sql = '''select u.id
                 from users u inner join beacons b
                 on u.beacon = b.telno
                 where b.locid=%s and u.telno=%s'''

        return self.fetchone(sql, locid, telno)[0]

    def user_telno(self, uid) -> 'telno' or Exception:
        if uid == ROOT_UID:
            return 'root'

        sql = '''select telno
                 from users u
                 where id = %s'''

        return self.fetchone(sql, uid)[0]

    def user_type(self, uid) -> UserType or Exception:
        if uid == ROOT_UID:
            return UserType.ADMIN

        sql = '''select user_type
                 from users
                 where id = %s'''

        return UserType(self.fetchone(sql, uid)[0])

    def user_type_by_telno(self, telno) -> UserType or Exception:
        if telno == 'root':
            return UserType.ADMIN

        sql = '''select user_type
                 from users
                 where telno = %s'''

        return UserType(self.fetchone(sql, telno)[0])

    def users_of_type(self, locid, *user_types) -> {"telno": ('id', 'user_type', 'nickname', 'ban_reason')} or None:
        sql = '''select u.telno, u.id, u.user_type, u.nickname, u.ban_reason
                 from users u inner join beacons b
                 on u.beacon = b.telno
                 where b.locid = %s
                 and u.user_type in ({})
        '''.format(','.join(str(ut) for ut in user_types))

        return { t[0]: t[1:] for t in self.fetchall(sql, locid) }

    def delete_user(self, uid):
        try:
            sql = '''delete from users where uid = %s'''
            return bool(self.execute(sql, uid))
        except:
            return False

    def beacon_nickname(self, locid) -> str:
        sql = '''select nickname
                 from beacons
                 where locid = %s'''

        try:
            return self.fetchone(sql, locid)[0]
        except:
            return ''

    def beacon_telno(self, locid) -> str:
        sql = '''select telno
                 from beacons
                 where locid = %s'''

        return self.fetchone(sql, locid)[0]

    def beacon_autosend_delay(self, locid) -> int:
        sql = 'select autosend_delay from beacons where locid = %s'
        return self.fetchone(sql, locid)[0]

    def beacon_prune_delay(self, locid) -> int:
        sql = 'select prune_delay from beacons where locid = %s'
        return self.fetchone(sql, locid)[0]

    def alert_details(self, aid) -> ('text', 'sender'):
        sql = 'select text, telno from alerts where id = %s'
        return self.fetchone(sql, aid)

    def user_token_lifetime(self, uid):
        sql = '''select b.token_lifetime
                 from beacons b inner join users u
                 on b.telno = u.beacon
                 where u.id=%s'''

        return self.fetchone(sql, uid)[0]

    def password_set(self, uid) -> bool:
        sql = '''select id
                 from users
                 where id=%s and phash is not null'''
        try:
            return bool(self.execute(sql, uid))
        except:
            return False

    def get_token(self, uid) -> ('thash', 'token_expires'):
        sql = '''select thash, token_expires
                 from users
                 where id=%s'''

        return self.fetchone(sql, uid)

    def get_api_keys(self, locid) -> ('id', 'token'):
        sql = 'select plivo_id, plivo_token from beacons where locid=%s'
        return self.fetchone(sql, locid)

    def init_root_user(self, thash):
        now = int(datetime.now().timestamp())
        self.insert_into('users',
            telno='root',
            beacon='root',
            user_type=UserType.ADMIN,
            thash=thash,
            token_expires= now + config.root_token_lifetime,
            created=now)

    def subscribe(self, user_telno, beacon_telno) -> 'uid':
        now = int(datetime.now().timestamp())

        # delete user if already there
        self.execute('delete from users where telno = %s and beacon = %s', user_telno, beacon_telno)

        return self.insert_into('users',
            telno=user_telno,
            beacon=beacon_telno,
            user_type=UserType.SUBSCRIBED,
            created=now)

    def unsubscribe(self, user_telno, beacon_telno) -> 'uid':
        now = int(datetime.now().timestamp())

        # delete user if already there
        self.execute('delete from users where telno = %s and beacon = %s', user_telno, beacon_telno)

        return self.insert_into('users',
            telno=user_telno,
            beacon=beacon_telno,
            user_type=UserType.NOT_SUBSCRIBED,
            created=now)

    def change_alert_type(self, aid, new_alert_type, uid):
        now = int(datetime.now().timestamp())

        # TODO: combine DB calls
        self.update('alerts', {'alert_type': new_alert_type, 'acted_at': now, 'acted_by': self.user_telno(uid)}, {'id': aid})

        if new_alert_type == AlertType.REPORT_RELAYED:
            self.execute('update users set num_relayed = num_relayed + 1 where id = %s', uid)
        elif new_alert_type == AlertType.REPORT_RELAYED:
            self.execute('update users set num_rejected = num_rejected + 1 where id = %s', uid)
