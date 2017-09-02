#!/usr/bin/env python3

import config
from app import UserType
from db import Database
from utils import random_token
from datetime import datetime

from passlib.context import CryptContext
crypto = CryptContext(schemes=['pbkdf2_sha256'])

from subprocess import check_call

# TODO actually create database

print("Populating database...", end=' ')
with open('schema.sql', 'r') as f:
    check_call(['mysql',
        '--host=' + config.database['host'],
        '--user=' + config.database['user'],
        '--password=' + config.database['password'],
        '--default-character-set=' + config.database['charset'],
        config.database['database']], stdin=f)

print("Done!\nConnecting to database...", end=' ')
db = Database()

print("Done!\nInitializing beacon root user...", end=' ')
root_token = random_token()
now = int(datetime.now().timestamp())
db.insert_into('users',
    telno='root',
    beacon='root',
    user_type=UserType.ADMIN,
    thash=crypto.hash(root_token),
    token_expires= now + config.root_token_lifetime,
    created=now)
print("Done!\n\nRoot user initialized. Run the app with ./app.py, then set the root password at:\nhttp://localhost:5000/root/login/" + root_token)
