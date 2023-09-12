from http import HTTPStatus
from unittest import mock

from django.core.cache import caches
from rest_framework.test import APIRequestFactory

from django_hmac_authentication.exceptions import KeyKillSwitchException
from tests.testing_utils import TestHMACAuthenticationBase


class TestHmacKillSwitch(TestHMACAuthenticationBase):
    def test_hmac_authentication__hmac_kill_switch(self):
        factory = APIRequestFactory()
        with mock.patch(
            'django_hmac_authentication.server_utils.hmac_cache_alias',
            'default',
        ):
            with mock.patch(
                'django_hmac_authentication.authentication.hmac_kill_switch_on',
                True,
            ):
                signature, utc_8601 = self._request_auth_header_fields(
                    '', 'HMAC-SHA512'
                )
                headers = {
                    f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
                    'Content-Type': 'application/json',
                }
                # set cache
                cache_key = f'HMAC_KILL_SWITCH__{self.hmac_key.id}'
                caches['default'].set(cache_key, True, timeout=100)

                request = factory.get('/', data=None, **headers)
                response = self.view(request)
                self.assertEqual(
                    response.status_code,
                    HTTPStatus.FORBIDDEN,
                    'Authentication must fail with hmac kill switch',
                )
                self._assert_response_error_detail(
                    response.data, KeyKillSwitchException()
                )

                # unset cache
                caches['default'].delete(cache_key)
