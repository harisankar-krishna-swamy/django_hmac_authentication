from http import HTTPStatus
from unittest import mock

from rest_framework.test import APIRequestFactory

from tests.testing_utils import TestHMACAuthenticationBase


class TestHmacAuthHeaderName(TestHMACAuthenticationBase):
    def test_hmac_authentication__hmac_auth_header_name(self):
        self.auth_header = 'TEST_HMAC_HEADER_NAME'
        factory = APIRequestFactory()
        req_data = ''
        with mock.patch(
            'django_hmac_authentication.authentication.hmac_auth_header_name',
            self.auth_header,
        ):
            signature, utc_8601 = self._request_auth_header_fields(
                req_data, 'HMAC-SHA512'
            )
            headers = {
                f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
                'Content-Type': 'application/json',
            }
            request = factory.get('/', data=None, **headers)
            response = self.view(request)
            self.assertEqual(
                response.status_code,
                HTTPStatus.OK,
                'Authentication must work with configured auth header name',
            )
