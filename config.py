# smsbeacon settings

# passed as kwargs to db.connect
database = dict(host="localhost",
                database="smsbeacon",
                user="smsbeacon",
                password="changeme",
                charset='utf8mb4')

# publicly accessible URL or IP used to access the site on the internet,
# without http(s):// prefix
public_url = "localhost"
port = 80

root_token_lifetime = 5 * 60
plivo_url_secret_length = 32
send_attempts = 3
resend_on_errors = (20, 30, 80, 90, 300)

flask_secret_key = 'change me'
processing_key = 'change me too, but not to the same thing'
