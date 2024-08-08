import copy
from datetime import timedelta
from unittest import mock

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
)
from django_hmac_authentication.server_utils import (
    get_api_hmac_key,
    timedelta_from_config,
)
from tests.factories import ApiHMACKeyFactory, ApiHMACKeyUserFactory

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


@ddt
class TestUtils(TestCase):
    # expires_in config, timedelta, exception
    @data(
        (None, None, TypeError),
        ('', None, TypeError),
        ('20d', None, ValueError),
        ('0h', None, ValueError),
        ('10h', timedelta(hours=10), None),
        ('15m', timedelta(minutes=15), None),
        ('3600s', timedelta(seconds=3600), None),
    )
    @unpack
    def test_timedelta_from_config(
        self, expires_in='1h', expected_timedelta=timedelta(hours=1), exc=None
    ):
        if exc:
            with self.assertRaises(exc):
                _ = timedelta_from_config(expires_in)
        else:
            td = timedelta_from_config(expires_in)
            self.assertEqual(
                expected_timedelta,
                td,
                f'calculated timedelta did not match expected value for input {expires_in}',
            )

    def test_get_api_hmac_key__caching(self):
        user = ApiHMACKeyUserFactory()
        hmac_key = ApiHMACKeyFactory(user=user)
        with self.assertNumQueries(1):
            db_hmac_key = get_api_hmac_key(hmac_key.id)
            self.assertTrue(
                db_hmac_key.id == hmac_key.id,
                'HMAC Key retrieved from db did not match original key',
            )

        name = 'HMAC_CACHE_ALIAS'
        from django.conf import settings

        hmac_settings = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        orig_value = copy.deepcopy(hmac_settings)
        hmac_settings[name] = 'default'

        with mock.patch(
            'django_hmac_authentication.server_utils.hmac_cache_alias',
            'default',
        ):
            with self.assertNumQueries(1):
                _ = get_api_hmac_key(hmac_key.id)
            with self.assertNumQueries(0):
                cached_hmac_key = get_api_hmac_key(hmac_key.id)
                self.assertTrue(
                    cached_hmac_key.id == hmac_key.id,
                    'HMAC Key retrieved from cache did not match original key',
                )

        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)
