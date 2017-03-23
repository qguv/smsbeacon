unsubscribe = ["stop", "unsubscribe", "unsub", "quit", "remove", "opt-out", "opt out"]
subscribe = ["subscribe", "register",
    "sign up", "sign me up", "sign this number up", "sign my number up", "sign my phone up", "sign my cell up",
    "add me", "add this number", "add my number", "add my phone", "add my cell"]

has_subscribe_phrase = lambda text: any(phrase in text.lower() for phrase in subscribe)
