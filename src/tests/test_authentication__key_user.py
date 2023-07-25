from http import HTTPStatus

from rest_framework.test import APIRequestFactory

from django_hmac_authentication.exceptions import (
    KeyDoesNotExistException,
    RevokedKeyException,
)
from tests.testing_utils import TestHMACAuthenticationBase


class TestKeyAndUserAttributes(TestHMACAuthenticationBase):
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
        self._assert_response_error_detail(response.data, RevokedKeyException())

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

    def test_hmac_authentication__non_existing_key(self):
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        # non existing key id
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 12345d23-595f-4fbc-bb32-716c183f3d0b;{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Non existing key must fail authentication',
        )
        self._assert_response_error_detail(response.data, KeyDoesNotExistException())
