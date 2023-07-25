import base64
from datetime import datetime, timezone

from rest_framework.response import Response
from rest_framework.test import APITestCase
from rest_framework.views import APIView

from django_hmac_authentication.authentication import HMACAuthentication
from django_hmac_authentication.client_utils import prepare_string_to_sign, sign_string
from django_hmac_authentication.server_utils import aes_decrypt_hmac_secret
from tests.factories import ApiHMACKeyFactory, ApiHMACKeyUserFactory


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


class TestHMACAuthenticationBase(APITestCase):
    def setUp(self) -> None:
        self.user = ApiHMACKeyUserFactory()
        self.hmac_key = ApiHMACKeyFactory(user=self.user)
        self.enc_secret = base64.b64decode(self.hmac_key.secret.encode('utf-8'))
        self.enc_salt = base64.b64decode(self.hmac_key.salt.encode('utf-8'))
        self.auth = HMACAuthentication()
        self.auth_header = 'HTTP_AUTHORIZATION'
        self.view = TestView.as_view()

    def _assert_response_error_detail(self, resp_data, exc):
        detail, code = resp_data.get('detail'), resp_data.get('detail').code
        self.assertEqual(
            detail,
            exc.detail,
            f'Response error detail did not match expected {exc.detail}',
        )
        self.assertEqual(
            code,
            exc.detail.code,
            f'Response error code did not match expected {exc.detail.code}',
        )

    def _request_auth_header_fields(self, req_data, digest):
        secret = aes_decrypt_hmac_secret(self.enc_secret, self.enc_salt)
        utc_8601 = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        string_to_sign = prepare_string_to_sign(req_data, utc_8601, digest)
        signature = sign_string(string_to_sign, secret, digest)
        return signature, utc_8601
