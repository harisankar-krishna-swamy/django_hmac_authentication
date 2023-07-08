import os
from datetime import timedelta
from unittest import mock

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.aes import aes_crypt
from django_hmac_authentication.client_utils import hash_content, sign_string
from django_hmac_authentication.server_utils import (
    aes_decrypt_hmac_secret,
    aes_encrypted_hmac_secret,
    get_api_hmac_key,
    timedelta_from_config,
)
from tests.factories import ApiHMACKeyFactory, ApiHMACKeyUserFactory


@ddt
class TestUtils(TestCase):
    def test_match_hmac_secret(self):
        hmac_secret, encrypted, enc_key, salt = aes_encrypted_hmac_secret()
        decrypted = aes_decrypt_hmac_secret(encrypted, salt)
        self.assertTrue(
            hmac_secret == decrypted, 'Decrypted secret did not match original'
        )

    def test_aes_crypt(self):
        msg = 'test_message'.encode('utf-8')
        key = os.urandom(32)
        iv = os.urandom(16)

        encrypted = aes_crypt(msg, key, iv, encrypt=True)
        decrypted = aes_crypt(encrypted, key, iv, encrypt=False)
        self.assertTrue(msg == decrypted, 'Decrypted message did not match original')

    @data(
        (
            'HMAC-SHA512',
            'test_message',
            '/6lk2bC3td2pofMQOdywLPTmYQM6MP3b5gmGm9azYz8SIac1lqmITl5zJ1NdUzykMg/w2k55Ib/EznURl67rUw==',
        ),
        (
            'HMAC-SHA384',
            'test_message',
            'gYw6VAI5YA7ykdU5N1PSP/UCGLdN2znASixGZ5wlT0wbLGxnmahafTvbqWOIpCfB',
        ),
        ('HMAC-SHA256', 'test_message', 'O3SR3AFqwaCy4CNyQCyGH6+kWSlAh+fL4J9wTVgtkx8='),
        ('HMAC-SHA256', '', None),
        ('HMAC-SHA256', None, None),
    )
    @unpack
    def test_hash_content(
        self,
        digest='HMAC-SHA256',
        content='test_message',
        expected_b64hash='O3SR3AFqwaCy4CNyQCyGH6+kWSlAh+fL4J9wTVgtkx8',
    ):
        content_by = content.encode('utf-8') if content else None
        calculated_b64hash = hash_content(digest, content_by)
        self.assertTrue(
            calculated_b64hash == expected_b64hash,
            f'Computed hash did not match expected for {digest}',
        )

    @data(
        (
            'HMAC-SHA512',
            'BsDXXZ895Ko1KhznDwBhRBS0+g+5X+KoZz1b3R7JUXhQ/5r0Q+pN+FfhlL88KRiL3ya2RNw6GETHbzolHcuXAw==',
        ),
        (
            'HMAC-SHA384',
            'd/bLM3PsSDS+/NxNqYwlqY9nNv/5OK9MJSd31uQ4cHB4DE9NIhG1cszPEgwJdu4+',
        ),
        (
            'HMAC-SHA256',
            'ZaIJF7XWibQHwbbgx6qd5AIh78SB/+WPJIXFHYIqzs4=',
        ),
    )
    @unpack
    def test_sign_string(
        self,
        digest='HMAC-SHA512',
        expected_b64signature='ZaIJF7XWibQHwbbgx6qd5AIh78SB/+WPJIXFHYIqzs4=',
    ):
        secret = 'test_secret'.encode('utf-8')
        message = 'test_message'
        calculated_b64signature = sign_string(message, secret, digest)
        self.assertTrue(
            calculated_b64signature == expected_b64signature,
            f'Computed signature did not match expected for {digest}',
        )

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

        orig_value = getattr(settings, name, None)
        setattr(settings, name, 'default')

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

        setattr(settings, name, orig_value)
