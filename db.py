from pymysql import connect
from config import database
from utils import call_some

class Database:

    def __init__(self):
        self.db = connect(**database)

    def insert_into(self, table, **kwargs):
        keys, values = zip(*kwargs.items())

        # get string representation, but leave None alone
        values = [ call_some(v, str) for v in values ]

        params = ', '.join(['%s'] * len(keys))
        columns = ', '.join('`{}`'.format(k) for k in keys)

        with self.db.cursor() as c:
            c.execute('insert into `{}` ({}) values ({})'.format(table, columns, params), values)
        self.db.commit()

    def update(self, table, updates=dict(), wheres=dict()):
        update_keys, update_values = zip(*updates.items())
        where_keys, where_values = zip(*wheres.items())

        # get string representation, but leave None alone
        update_values = list(map(lambda v: call_some(v, str), update_values))
        where_values = list(map(lambda v: call_some(v, str), where_values))

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
        with self.db.cursor() as c:
            c.execute(sql, *replacements)
            return c.fetchone()

    def fetchall(self, sql, *replacements):
        with self.db.cursor() as c:
            c.execute(sql, *replacements)
            return c.fetchall()

    def cursor(self):
        return self.db.cursor()

    def close(self):
        return self.db.close()
