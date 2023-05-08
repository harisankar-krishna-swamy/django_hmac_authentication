import base64
import json

import requests

from django_hmac_authentication.client_utils import (
    compose_authorization_header,
    hmac_sign,
)

json_response = '''
{"api_key":"389a037f-807b-4222-9a53-d809f2e6d122",
"api_secret":"/ZUSi2Krv84Ke4L9HeeoogKKg0w7/UBzMSKgX4WP7tU=",
"message":"These credentials will be lost forever if not stored now"}
'''

if __name__ == '__main__':

    response_data = json.loads(json_response)
    api_key = response_data['api_key']
    api_secret = base64.b64decode(response_data['api_secret'])
    url = 'http://127.0.0.1:8000/accounts/an-authenticated-view/'

    digest = 'HMAC-SHA512'
    # GET
    signature, utc8601 = hmac_sign(None, api_secret, digest)
    authorization_header = compose_authorization_header(
        digest, api_key, signature, utc8601
    )
    headers = {'Authorization': authorization_header}
    r = requests.get(url, headers=headers)
    assert r.status_code == 200

    # POST
    req_data = {'a': 1, 'b': 2}
    signature, utc8601 = hmac_sign(req_data, api_secret, digest)
    authorization_header = compose_authorization_header(
        digest, api_key, signature, utc8601
    )
    headers = {
        'Authorization': authorization_header,
        'Content-Type': 'application/json',
    }

    r = requests.post(url, json=req_data, headers=headers)
    assert r.status_code == 200
