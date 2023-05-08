from http import HTTPStatus

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from django_hmac_authentication.views import CreateApiHMACKey
from tests.factories import ApiHMACKeyUserFactory, test_password

factory = APIRequestFactory()


class TestViewCreateApiKey(TestCase):
    def setUp(self) -> None:
        self.user = ApiHMACKeyUserFactory()
        self.view = CreateApiHMACKey.as_view()

    def _assert_http_ok_key_reponse(self, response):
        self.assertEqual(
            HTTPStatus.OK, response.status_code, 'Invalid status on getting api key'
        )
        for item in (
            'api_key',
            'api_secret',
            'message',
        ):
            self.assertIn(item, response.data, f'item {item} missing in response')
            self.assertTrue(response.data[item], f'item {item} is empty in response')

    def test_view__create_api_hmac_key(self):
        data = {'username': self.user.username, 'password': test_password}
        request = factory.post('/', data=data, format='json')
        response = self.view(request)
        self._assert_http_ok_key_reponse(response)

    def test_view__max_keys_per_user(self):
        from django.conf import settings

        for i in range(0, settings.MAX_HMACS_PER_USER + 1):
            data = {'username': self.user.username, 'password': test_password}
            request = factory.post('/', data=data, format='json')
            response = self.view(request)
            if i < settings.MAX_HMACS_PER_USER:
                self._assert_http_ok_key_reponse(response)
            else:
                self.assertEqual(
                    HTTPStatus.BAD_REQUEST,
                    response.status_code,
                    'Validation error must be raised on reaching MAX_HMACS_PER_USER',
                )
