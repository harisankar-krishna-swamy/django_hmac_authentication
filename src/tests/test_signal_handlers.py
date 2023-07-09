from unittest import mock

from django.test import TestCase

from django_hmac_authentication.server_utils import get_api_hmac_key
from tests.factories import ApiHMACKeyFactory, ApiHMACKeyUserFactory


class TestSignalHandlers(TestCase):
    def setUp(self) -> None:
        self.user = ApiHMACKeyUserFactory()
        self.hmac_key = ApiHMACKeyFactory(user=self.user)

    def test_signal_handler__post_save__update_hmac_cache_on_save(self):
        name = 'HMAC_CACHE_ALIAS'
        from django.conf import settings

        orig_value = getattr(settings, name, None)
        setattr(settings, name, 'default')

        with mock.patch(
            'django_hmac_authentication.server_utils.hmac_cache_alias',
            'default',
        ):
            with mock.patch(
                'django_hmac_authentication.signals.hmac_cache_alias',
                'default',
            ):
                # trigger retrieval and cache
                cached_key = get_api_hmac_key(self.hmac_key.id)
                self.assertTrue(
                    cached_key.id == self.hmac_key.id,
                    'Cached key was different from original',
                )

                # change and save
                self.hmac_key.revoked = True
                self.hmac_key.save()
                self.hmac_key.refresh_from_db()

                key_post_save = get_api_hmac_key(self.hmac_key.id)
                self.assertTrue(
                    self.hmac_key.id == key_post_save.id,
                    'Cached key was different after trigerring post_save signal handler',
                )
                self.assertTrue(
                    self.hmac_key.revoked == key_post_save.revoked,
                    'post_save signal handler was not invoked to update cache',
                )

        setattr(settings, name, orig_value)
