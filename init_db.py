#!/usr/bin/env python3

# allow importing dependencies
import os, sys; sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./vendored"))

import config
from db import Database, UserType
from utils import random_token
from datetime import datetime

from passlib.context import CryptContext
crypto = CryptContext(schemes=['pbkdf2_sha256'])

from subprocess import check_call

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
db.init_root_user(crypto.hash(root_token))

url = config.public_url
if config.port != 80:
    url += ":{}".format(config.port)

sudo = 'sudo ' if config.port < 1024 else ''
print("Done!\n\nRoot user initialized. Run the app with:\n  {}python3 app.py\nthen set the root password at:\n  http://{}/root/login/{}".format(sudo, url, root_token))
