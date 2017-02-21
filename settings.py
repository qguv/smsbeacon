appname         = "beacon"
plivo_id        = "your_plivo_auth_id"
plivo_token     = "your_plivo_auth_token"

# your messages will clear the queue between (queue_interval * (veto_delay - 1))
# and (queue_interval * veto_delay) seconds

queue_interval  = 60 # seconds
veto_delay      = 3 # queue intervals to keep messages in the queue

vetoers = {
    "18885552468": "Quint",
}

initial_subscribers = [
    "18005550123",
]
