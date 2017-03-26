appname         = "beacon"
plivo_id        = "your_plivo_auth_id"
plivo_token     = "your_plivo_auth_token"
port            = 80

# Your app will be hosted with the value of root_key as a root URL, e.g. the
# receive_sms route is hosted at 111.111.111.111/your_root_key/receive_sms.
# This way, random people can't hit your app endpoint programmatically as a
# webapp and rack up charges on your account with impunity. Don't disclose this
# URL to anyone but plivo!
root_key        = "changethis"

# your messages will clear the queue between (queue_interval * (veto_delay - 1))
# and (queue_interval * veto_delay) seconds
queue_interval  = 60 # seconds
veto_delay      = 3

# name of the sqlite database, stored in the current directory
db_filename     = appname + ".db"

# who can veto messages, and whom to attribute their actions to
vetoers = {
    "37000000000": "Alice",
    "37200000000": "Mohammed",
    "37300000000": "Sophia",
}

# Automatically injected into the database when created. Useful for testing.
initial_subscribers = [
    "58000000000",
    "58200000000",
    "58300000000",
]

# Also injected into the database when created. Useful for testing.
initial_banned = [
    "84000000000",
]
