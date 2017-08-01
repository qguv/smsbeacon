#!/usr/bin/env python3

from settings import database
from app import make_root_user

from subprocess import check_call

print("Creating database...")
with open('schema.sql', 'r') as f:
    check_call(['mysql',
        '--user=' + database['user'],
        '--password=' + database['password'],
        '--default-character-set=' + database['charset'],
        database['database']], stdin=f)
print("Done!\nInitializing beacon root user...")

make_root_user()
