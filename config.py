# smsbeacon settings

# passed as kwargs to db.connect
database = dict(host="localhost",
                database="smsbeacon",
                user="smsbeacon",
                password="changeme",
                charset='utf8mb4')

port = 80

root_token_lifetime = 5 * 60
plivo_url_secret_length = 32

flask_secret_key = 'changeme'
