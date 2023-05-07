import base64
import datetime
import json

from ddt import data, ddt, unpack
from django.test import TestCase
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from django_hmac_authentication.authentication import HMACAuthentication
from django_hmac_authentication.utils import (
    aes_decrypt_hmac_secret,
    hash_content,
    message_signature,
)
from tests.factories import ApiSecretFactory, ApiSecretUserFactory


@ddt
class TestTokenAuthentication(TestCase):
    def setUp(self) -> None:
        self.user = ApiSecretUserFactory()
        self.api_secret = ApiSecretFactory(user=self.user)
        self.auth = HMACAuthentication()
        self.auth_header = 'HTTP_AUTHORIZATION'

    test_data__hmac_http_methods = (
        # hmac-sha512
        # ('hmac-sha512', 'GET', ),
        (
            'hmac-sha512',
            'POST',
        ),
        # ('hmac-sha512', 'PATCH', ),
        # ('hmac-sha512', 'PUT',),
        # ('hmac-sha512', 'DELETE', ),
        # hmac-sha256
        # ('hmac-sha256', 'GET', ),
        # ('hmac-sha256', 'POST',),
        # ('hmac-sha256', 'PATCH',),
        # ('hmac-sha256', 'PUT',),
        # ('hmac-sha256', 'DELETE',)
    )

    @data(*test_data__hmac_http_methods)
    @unpack
    def test_api_secret__authenticate__get__valid(
        self, digest='hmac-sha512', http_method='POST'
    ):
        factory = APIRequestFactory()
        req_data = ''
        if http_method in {'PUT', 'POST', 'PATCH'}:
            req_data = {'a': 1, 'b': 2}
        body = '' if not req_data else json.dumps(req_data, separators=(',', ':'))
        hash_body = hash_content(digest, body.encode('utf-8'))
        utc_8601 = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )

        enc_secret = base64.b64decode(self.api_secret.secret.encode('utf-8'))
        enc_salt = base64.b64decode(self.api_secret.salt.encode('utf-8'))

        secret = aes_decrypt_hmac_secret(enc_secret, enc_salt)
        signature = message_signature(f'{hash_body};{utc_8601}', secret, digest)

        headers = {
            f'{self.auth_header}': f'{digest} {self.api_secret.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        if http_method == 'GET':
            request = factory.get('api/commons/languages/', data=None, **headers)
        if http_method == 'PUT':
            request = factory.put(
                'api/commons/languages/', data=req_data, format='json', **headers
            )
        if http_method == 'POST':
            request = factory.post(
                'api/commons/languages/', data=req_data, format='json', **headers
            )
        if http_method == 'PATCH':
            request = factory.patch(
                'api/commons/languages/', data=req_data, format='json', **headers
            )
        if http_method == 'DELETE':
            request = factory.delete('api/commons/languages/', data=None, **headers)

        hash_body = hash_content(digest, request.body)

        user, auth = HMACAuthentication().authenticate(request)
        self.assertEqual(
            user,
            self.api_secret.user,
            f'User did not match expected after authentication with digest {digest} http_method {http_method}',
        )
        self.assertEqual(
            auth,
            None,
            'auth entry did not match expected after authentication',
        )
