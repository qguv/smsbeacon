class RestAPI:
    def __init__(self, plivo_id, plivo_token):
        pass

    def send_message(self, msg):
        print("\nPlivo message sent to {} from {}: {}".format(msg["dst"], msg["src"], msg["text"]))
