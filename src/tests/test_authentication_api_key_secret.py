import base64
import datetime
from datetime import timedelta
from http import HTTPStatus

from ddt import data, ddt, unpack
from freezegun import freeze_time
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase
from rest_framework.views import APIView

from django_hmac_authentication.authentication import HMACAuthentication
from django_hmac_authentication.client_utils import prepare_string_to_sign, sign_string
from django_hmac_authentication.server_utils import aes_decrypt_hmac_secret
from tests.factories import ApiHMACKeyFactory, ApiHMACKeyUserFactory
from tests.test_hmac_authorization_header_parsing import (
    test_data__authorization_header_parsing_invalid,
)


class TestView(APIView):
    authentication_classes = (HMACAuthentication,)

    def get(self, request):
        return Response(data={'method': 'GET'})

    def post(self, request):
        return Response(data={'method': 'POST'})

    def patch(self, request):
        return Response(data={'method': 'PATCH'})

    def put(self, request):
        return Response(data={'method': 'PUT'})

    def delete(self, request):
        return Response(data={'method': 'DELETE'})


@ddt
class TestHMACAuthentication(APITestCase):
    def setUp(self) -> None:
        self.user = ApiHMACKeyUserFactory()
        self.hmac_key = ApiHMACKeyFactory(user=self.user)
        self.enc_secret = base64.b64decode(self.hmac_key.secret.encode('utf-8'))
        self.enc_salt = base64.b64decode(self.hmac_key.salt.encode('utf-8'))
        self.auth = HMACAuthentication()
        self.auth_header = 'HTTP_AUTHORIZATION'
        self.view = TestView.as_view()

    def _request_auth_header_fields(self, req_data, digest):
        secret = aes_decrypt_hmac_secret(self.enc_secret, self.enc_salt)
        utc_8601 = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        string_to_sign = prepare_string_to_sign(req_data, utc_8601, digest)
        signature = sign_string(string_to_sign, secret, digest)
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
    def test_api__hmac_authenticate__valid(
        self, digest='HMAC-SHA512', http_method='POST'
    ):
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

    def test_hmac_authentication__revoked(self):
        self.hmac_key.revoked = True
        self.hmac_key.save()
        self.hmac_key.refresh_from_db()
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Revoked API key must fail authentication',
        )

    def test_hmac_authentication__inactive_user(self):
        self.user.is_active = False
        self.user.save()
        self.user.refresh_from_db()
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Inactive user must fail authentication',
        )

    def test_hmac_authentication__timeout(self):
        factory = APIRequestFactory()
        req_data = ''
        initial_datetime = datetime.datetime.utcnow() - timedelta(seconds=6)
        with freeze_time(initial_datetime):
            signature, utc_8601 = self._request_auth_header_fields(
                req_data, 'HMAC-SHA512'
            )

        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('api/commons/languages/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Timed out request must fail authentication',
        )

    @data(*test_data__authorization_header_parsing_invalid)
    @unpack
    def test_hmac_authentication__fail_malformed_header(
        self, header=None, valid_header=False
    ):
        factory = APIRequestFactory()
        headers = {
            f'{self.auth_header}': header,
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Authentication must fail on malformed header',
        )
