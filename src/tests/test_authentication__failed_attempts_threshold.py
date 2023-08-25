from http import HTTPStatus
from unittest import mock

from rest_framework.test import APIRequestFactory

from django_hmac_authentication.exceptions import SignatureVerificationException
from tests.testing_utils import TestHMACAuthenticationBase


class TestFailedAttemptsThreshold(TestHMACAuthenticationBase):
    def test_hmac_authentication__failed_attempts_threshold(self):
        test_failed_attempts_threshold = 5
        factory = APIRequestFactory()
        req_data = ''
        with mock.patch(
            'django_hmac_authentication.authentication.failed_attempts_threshold',
            test_failed_attempts_threshold,
        ):
            for i in range(1, test_failed_attempts_threshold + 1):
                signature, utc_8601 = self._request_auth_header_fields(
                    req_data, 'HMAC-SHA512'
                )
                invalid_signature = (
                    'dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=='
                )
                headers = {
                    f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{invalid_signature};{utc_8601}',
                    'Content-Type': 'application/json',
                }
                prev_failed_attempts = self.hmac_key.failed_attempts
                request = factory.get('/', data=None, **headers)
                response = self.view(request)
                self.assertEqual(
                    response.status_code,
                    HTTPStatus.FORBIDDEN,
                    'Invalid signature must fail authentication',
                )
                self.hmac_key.refresh_from_db()
                self.assertEqual(
                    self.hmac_key.failed_attempts,
                    prev_failed_attempts + 1,
                    'Failed attempts count did not match expected',
                )
                if i == test_failed_attempts_threshold:
                    self._assert_response_error_detail(
                        response.data,
                        SignatureVerificationException(
                            'Signature verification failed. Too many failed attempts. Key revoked.'
                        ),
                    )
                    self.assertTrue(
                        self.hmac_key.revoked,
                        'Key must be revoked on failed attempts threshold',
                    )
                elif i < test_failed_attempts_threshold:
                    self._assert_response_error_detail(
                        response.data, SignatureVerificationException()
                    )
