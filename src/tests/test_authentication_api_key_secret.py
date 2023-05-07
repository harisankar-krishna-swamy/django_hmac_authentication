import base64
import datetime
import json
from datetime import timedelta

from ddt import data, ddt, unpack
from django.test import TestCase
from freezegun import freeze_time
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
class TestHMACAuthentication(TestCase):
    def setUp(self) -> None:
        self.user = ApiSecretUserFactory()
        self.api_secret = ApiSecretFactory(user=self.user)
        self.enc_secret = base64.b64decode(self.api_secret.secret.encode('utf-8'))
        self.enc_salt = base64.b64decode(self.api_secret.salt.encode('utf-8'))
        self.auth = HMACAuthentication()
        self.auth_header = 'HTTP_AUTHORIZATION'

    def _request_auth_header_fields(self, req_data, digest):
        body = '' if not req_data else json.dumps(req_data, separators=(',', ':'))
        hash_body = hash_content(digest, body.encode('utf-8'))
        utc_8601 = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        secret = aes_decrypt_hmac_secret(self.enc_secret, self.enc_salt)
        signature = message_signature(f'{hash_body};{utc_8601}', secret, digest)
        return signature, utc_8601

    test_data__hmac_http_methods = (
        # hmac-sha512
        (
            'HMAC-SHA512',
            'GET',
        ),
        (
            'HMAC-SHA512',
            'POST',
        ),
        (
            'HMAC-SHA512',
            'PATCH',
        ),
        (
            'HMAC-SHA512',
            'PUT',
        ),
        (
            'HMAC-SHA512',
            'DELETE',
        ),
        # hmac-sha256
        (
            'HMAC-SHA256',
            'GET',
        ),
        (
            'HMAC-SHA256',
            'POST',
        ),
        (
            'HMAC-SHA256',
            'PATCH',
        ),
        (
            'HMAC-SHA256',
            'PUT',
        ),
        (
            'HMAC-SHA256',
            'DELETE',
        ),
    )

    @data(*test_data__hmac_http_methods)
    @unpack
    def test_api_secret__hmacauthenticate__valid(
        self, digest='HMAC-SHA512', http_method='POST'
    ):
        factory = APIRequestFactory()
        req_data = ''
        if http_method in {'PUT', 'POST', 'PATCH'}:
            req_data = {'a': 1, 'b': 2}

        signature, utc_8601 = self._request_auth_header_fields(req_data, digest)

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

    test_data__authorization_header_parsing__invalid = (
        # invalid values for authorization header content
        (None,),
        ('',),
        ('one_part',),
        ('two parts',),
        ('with three parts',),
        ('with such four parts',),
    )

    @data(*test_data__authorization_header_parsing__invalid)
    @unpack
    def test_hmac_authentication_authorization_header_parsing__invalid(
        self, header=None, expected_token=None
    ):
        header_parts = self.auth.parse_authorization_header(header)
        for part in header_parts:
            self.assertIsNone(
                part,
                f'Header parsing failed. Header part {part} when expecting None',
            )

    def test_hmac_authentication__revoked(self):
        self.api_secret.revoked = True
        self.api_secret.save()
        self.api_secret.refresh_from_db()
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        headers = {
            f'{self.auth_header}': f'hmac-sha512 {self.api_secret.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('api/commons/languages/', data=None, **headers)
        with self.assertRaises(AuthenticationFailed):
            _ = HMACAuthentication().authenticate(request)

    def test_hmac_authentication__inactive_user(self):
        self.user.is_active = False
        self.user.save()
        self.user.refresh_from_db()
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        headers = {
            f'{self.auth_header}': f'hmac-sha512 {self.api_secret.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('api/commons/languages/', data=None, **headers)
        with self.assertRaises(AuthenticationFailed):
            _ = HMACAuthentication().authenticate(request)

    def test_hmac_authentication__timeout(self):
        factory = APIRequestFactory()
        req_data = ''
        initial_datetime = datetime.datetime.utcnow() - timedelta(seconds=4)
        with freeze_time(initial_datetime):
            signature, utc_8601 = self._request_auth_header_fields(
                req_data, 'HMAC-SHA512'
            )

        headers = {
            f'{self.auth_header}': f'hmac-sha512 {self.api_secret.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('api/commons/languages/', data=None, **headers)
        with self.assertRaises(AuthenticationFailed):
            _ = HMACAuthentication().authenticate(request)
