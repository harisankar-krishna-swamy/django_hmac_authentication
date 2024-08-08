from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
)
from django_hmac_authentication.crypt.signatures import hash_content, sign_string

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


@ddt
class TestCryptSignatures(TestCase):
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
