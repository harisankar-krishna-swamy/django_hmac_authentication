from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest import mock

from rest_framework.test import APIRequestFactory

from django_hmac_authentication.exceptions import ExpiredKeyException
from django_hmac_authentication.settings import get_tz
from tests.testing_utils import TestHMACAuthenticationBase


class TestExpiresIn(TestHMACAuthenticationBase):
    def test_hmac_authentication__expires_in(self):
        initial_time = datetime.now(get_tz())
        test_expires_at = initial_time - timedelta(days=1)
        self.hmac_key.expires_at = test_expires_at
        self.hmac_key.save()
        self.hmac_key.refresh_from_db()
        factory = APIRequestFactory()
        req_data = ''
        with mock.patch(
            'django_hmac_authentication.authentication.hmac_expires_in',
            '1d',
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
                HTTPStatus.FORBIDDEN,
                'Expired key must fail authentication',
            )
            self._assert_response_error_detail(response.data, ExpiredKeyException())
