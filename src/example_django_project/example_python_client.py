import base64
import datetime
import json

import requests

from django_hmac_authentication.client_utils import (
    compose_authorization_header,
    prepare_string_to_sign,
    sign_string,
)


def get_api_key_secret(url, username, password):
    # Get API key and secret for Django user
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data)
    resp_data = json.loads(response.text)
    api_key, api_secret = resp_data['api_key'], resp_data['api_secret']

    return api_key, api_secret


if __name__ == '__main__':

    api_key, api_secret = get_api_key_secret(
        'http://127.0.0.1:8000/obtain-hmac-api-key/', 'bob', 'bobspassword'
    )
    api_secret = base64.b64decode(api_secret)

    url = 'http://127.0.0.1:8000/accounts/an-authenticated-view/'

    digest = 'HMAC-SHA512'
    utc_8601 = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )

    # GET example
    string_to_sign = prepare_string_to_sign(None, utc_8601, digest)
    signature = sign_string(string_to_sign, api_secret, digest)
    authorization_header = compose_authorization_header(
        digest, api_key, signature, utc_8601
    )
    headers = {'Authorization': authorization_header}
    r = requests.get(url, headers=headers)
    assert r.status_code == 200

    # POST example
    req_data = {'a': 1, 'b': 2}
    string_to_sign = prepare_string_to_sign(req_data, utc_8601, digest)
    signature = sign_string(string_to_sign, api_secret, digest)
    authorization_header = compose_authorization_header(
        digest, api_key, signature, utc_8601
    )
    headers = {
        'Authorization': authorization_header,
        'Content-Type': 'application/json',
    }

    r = requests.post(url, json=req_data, headers=headers)
    assert r.status_code == 200
