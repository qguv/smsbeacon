appname         = "beacon"
plivo_id        = "your_plivo_auth_id"
plivo_token     = "your_plivo_auth_token"

db_filename     = appname + ".db"

# your messages will clear the queue between (queue_interval * (veto_delay - 1))
# and (queue_interval * veto_delay) seconds

queue_interval  = 60 # seconds
veto_delay      = 3 # queue intervals to keep messages in the queue

vetoers = {
    "37000000000": "Quint",
    "37200000000": "someone else",
    "37300000000": "someone else",
}

initial_subscribers = [
    "58000000000",
    "58200000000",
    "58300000000",
]

initial_banned = [
    "84000000000",
]
