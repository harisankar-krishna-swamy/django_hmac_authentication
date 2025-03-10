import base64
from http import HTTPStatus

from ddt import data, ddt, unpack
from rest_framework.test import APIRequestFactory
from vevde_security_utils.crypt.hmac import cipher_encrypted_hmac_secret
from vevde_security_utils.crypt.settings import SUPPORTED_CIPHERS

from django_hmac_authentication.authentication import HMACAuthentication
from tests.factories import ApiHMACKeyFactory, hmac_kd_password
from tests.testing_utils import TestHMACAuthenticationBase

HTTP_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')

test_data = []
for http_method in HTTP_METHODS:
    for auth_method in HMACAuthentication.authentication_methods:
        for cipher_algorithm in SUPPORTED_CIPHERS:
            test_data.append((auth_method, http_method, cipher_algorithm))


@ddt
class TestHMACAuthentication(TestHMACAuthenticationBase):
    @data(*test_data)
    @unpack
    def test_api__hmac_authenticate__valid(
        self, digest='HMAC-SHA512', http_method='POST', cipher_algorithm='AES-256'
    ):
        self.hmac_key.delete()
        # build required hmac key
        (
            test_hmac_secret,
            test_encrypted,
            test_enc_key,
            test_salt,
        ) = cipher_encrypted_hmac_secret(hmac_kd_password, cipher_algorithm)
        self.hmac_key = ApiHMACKeyFactory(
            user=self.user,
            salt=base64.b64encode(test_salt).decode('utf-8'),
            secret=base64.b64encode(test_encrypted).decode('utf-8'),
            cipher_algorithm=cipher_algorithm,
        )
        self.enc_secret = base64.b64decode(self.hmac_key.secret.encode('utf-8'))
        self.enc_salt = base64.b64decode(self.hmac_key.salt.encode('utf-8'))

        factory = APIRequestFactory()
        req_data = None
        if http_method in {'PUT', 'POST', 'PATCH'}:
            req_data = {'a': 1, 'b': 2}

        signature, utc_8601 = self._request_auth_header_fields(req_data, digest)

        headers = {
            f'{self.auth_header}': f'{digest} {self.hmac_key.id};{signature};{utc_8601}',
        }
        if http_method == 'GET':
            request = factory.get('/', data=None, **headers)

        if http_method == 'PUT':
            request = factory.put('/', data=req_data, format='json', **headers)
        if http_method == 'POST':
            request = factory.post('/', data=req_data, format='json', **headers)
        if http_method == 'PATCH':
            request = factory.patch('/', data=req_data, format='json', **headers)
        if http_method == 'DELETE':
            request = factory.delete('/', data=None, **headers)

        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.OK,
            f'Authentication failed with digest {digest} http_method {http_method}',
        )
