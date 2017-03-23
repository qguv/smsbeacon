#!/usr/bin/env python3

import requests

try:
    host = input("Host? [enter for localhost] ")
    if not host:
        host = "localhost"

    port = input("Which port is the app listening on? [enter for 8888] ")
    try:
        port = int(port)
    except ValueError:
        port = 8888

    dst  = input("To:   ") or "11111111111"

    while True:
        src = {"v": "37000000000",
               "s": "58000000000",
               "b": "84000000000",
               "u": "11000000000"}.get(input("Role: ").strip(), None)

        if src is None:
            src = input("From: ").strip()

        text = input("Message: ")
        print(requests.get("http://{}:{}/receive_sms/".format(host, port), params={"From": src, "To": dst, "Text": text}).text)

except KeyboardInterrupt:
    print("\nbye")
