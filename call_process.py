#!/usr/bin/env python3
'''Incredibly ugly hack to call process route regularly. TODO: use SQS instead'''

def handler(*args):
    import requests # external
    import config   # internal

    protocol = "https" if config.https else "http"
    port = '' if config.port == 80 else ':{}'.format(port)

    url = protocol + '://' + config.public_url + port + '/p/' + config.processing_key

    return requests.get(url)
