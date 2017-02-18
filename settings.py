appname         = "beacon"
plivo_id        = "your_plivo_auth_id"
plivo_token     = "your_plivo_auth_token"
plivo_number    = "18665551234"
endpoint        = "http://beacon.example.com/" # with trailing slash
queue_interval  = 60 # seconds
veto_delay      = 4 # queue intervals

vetoers = {
    "18885552468": "Quint",
}

subscribers = [
    "18005550123",
]
