#!/usr/bin/env python3
'''Incredibly ugly hack to call process route regularly. TODO: use SQS instead'''

import urllib.request, urllib.error
import config # internal

def handler(*args):
    protocol = "https" if config.https else "http"
    port = '' if config.port == 80 else ':{}'.format(port)

    url = protocol + '://' + config.public_url + port + '/p/' + config.processing_key

    try:
        urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        print("HTTP Error {}: {}".format(*e.reason))
