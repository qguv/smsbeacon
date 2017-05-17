appname         = "beacon"
plivo_id        = "your_plivo_auth_id"
plivo_token     = "your_plivo_auth_token"
port            = 8086

db_host         = "localhost"
db_port         = 3306
db_database     = "beacon"
db_user         = "changethis"
db_password     = "changethis"

# Your app will be hosted with the value of root_key as a root URL, e.g. the
# receive_sms route is hosted at 111.111.111.111/your_root_key/. This way,
# random people can't hit your app endpoint programmatically as a webapp and
# rack up charges on your account with impunity. Don't disclose this URL to
# anyone but plivo!
root_key        = "changethis"

# If nobody responds, your messages will clear the queue between
# (queue_interval * (veto_delay - 1)) and (queue_interval * veto_delay)
# seconds. If an investigator volunteers to check it out, they will clear
# between (queue_interval * (investigate_delay - 1)) and (queue_interval *
# investigate_delay) seconds after the investigator's response.
queue_interval  = 60 # seconds
veto_delay      = 3
investigate_delay = 30

# "Shadowbanning" is when an app pretends to respond to banned users "like
# normal" when in reality the actions of the banned user don't affect anyone
# else. Setting to True is more expensive, wasting resources to respond to
# known spammers, but may prevent less intelligent spammers from evading bans.
shadowbans      = False

# automatically injected into the database when it's created.
db_init = {

    # for each deploy number
    "83400000000": {

        # community covered by this beacon (required)
        "community": "first community",

        # name of the app (optional, default is 'beacon')
        "name": "first",

        # numbers to automatically subscribe (optional)
        "subscribers": [
            "58000000000",
            "58200000000",
            "58300000000",
        ],

        # numbers to ban (optional)
        "banned": [
            "84000000000",
        ],

        # numbers and names to set up as investigators (optional)
        "investigators": {
            "37000000000": "Alice",
            "37200000000": "Mohammed",
            "37300000000": "Sophia",
        },

        # number used as an alias (optional, deprecated)
        "alias": "83499999999",
    },
}
