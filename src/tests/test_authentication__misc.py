from datetime import datetime, timedelta
from http import HTTPStatus

from ddt import data, ddt, unpack
from freezegun import freeze_time
from rest_framework.test import APIRequestFactory

from django_hmac_authentication.exceptions import (
    DateFormatException,
    ExpiredRequestException,
    FutureRequestException,
    SignatureVerificationException,
    UnsupportedHMACMethodException,
)
from tests.test_hmac_authorization_header_parsing import (
    test_data__authorization_header_parsing_invalid,
)
from tests.testing_utils import TestHMACAuthenticationBase


@ddt
class TestMisc(TestHMACAuthenticationBase):
    def test_hmac_authentication__timeout(self):
        factory = APIRequestFactory()
        req_data = ''
        initial_datetime = datetime.utcnow() - timedelta(seconds=6)
        with freeze_time(initial_datetime):
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
            'Timed out request must fail authentication',
        )
        self._assert_response_error_detail(response.data, ExpiredRequestException())

    def test_hmac_authentication__future_request(self):
        factory = APIRequestFactory()
        req_data = ''
        initial_datetime = datetime.utcnow() + timedelta(seconds=6)
        with freeze_time(initial_datetime):
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
            'Future timed request must fail authentication',
        )
        self._assert_response_error_detail(response.data, FutureRequestException())

    def test_hmac_authentication__unsupported_hmac_method(self):
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        # Unsupported hmac method
        headers = {
            f'{self.auth_header}': f'HMAC-SHA123 {self.hmac_key.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Unsupported hmac method must fail authentication',
        )
        self._assert_response_error_detail(
            response.data, UnsupportedHMACMethodException(hmac_method='HMAC-SHA123')
        )

    def test_hmac_authentication__malformed_date_str(self):
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        # malformed date
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};malformed_date+0:0',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Malformed date must fail authentication',
        )
        self._assert_response_error_detail(response.data, DateFormatException())

    def test_hmac_authentication__invalid_signature(self):
        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        invalid_signature = (
            'dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=='
        )
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{invalid_signature};{utc_8601}',
            'Content-Type': 'application/json',
        }
        request = factory.get('/', data=None, **headers)
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.FORBIDDEN,
            'Invalid signature must fail authentication',
        )
        self._assert_response_error_detail(
            response.data, SignatureVerificationException()
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
