import copy
from http import HTTPStatus

from rest_framework.test import APIRequestFactory

from django_hmac_authentication.settings import DEFAULTS
from tests.testing_utils import TestHMACAuthenticationBase, TestThrottleView


class ThrottlingTests(TestHMACAuthenticationBase):
    def setUp(self) -> None:
        super().setUp()
        self.view = TestThrottleView.as_view()
        self.throttle_rate = 10
        self.hmac_key.throttle_rate = f'{self.throttle_rate}/day'
        self.hmac_key.save()
        self.hmac_key.refresh_from_db()

    def test__throttling(self):
        from django.conf import settings

        hmac_settings = copy.deepcopy(DEFAULTS)
        hmac_settings.update({'HMAC_CACHE_ALIAS': 'default'})
        orig_value = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', hmac_settings)

        factory = APIRequestFactory()
        req_data = ''
        signature, utc_8601 = self._request_auth_header_fields(req_data, 'HMAC-SHA512')
        headers = {
            f'{self.auth_header}': f'HMAC-SHA512 {self.hmac_key.id};{signature};{utc_8601}',
            'Content-Type': 'application/json',
        }

        request = factory.get('/', data=None, **headers)
        for i in range(self.throttle_rate):
            response = self.view(request)
            self.assertEqual(
                response.status_code,
                HTTPStatus.OK,
                'Requests within throttle rate must succeed',
            )
        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.TOO_MANY_REQUESTS,
            'Requests exceeding throttle rate must return with HTTP 429',
        )

        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)
