import os

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.aes import aes_crypt
from django_hmac_authentication.client_utils import hash_content, sign_string
from django_hmac_authentication.server_utils import (
    aes_decrypt_hmac_secret,
    aes_encrypted_hmac_secret,
)


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
