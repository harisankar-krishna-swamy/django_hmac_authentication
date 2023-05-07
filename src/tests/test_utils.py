import os

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.aes import aes_crypt
from django_hmac_authentication.utils import (
    aes_decrypt_hmac_secret,
    aes_encrypt_hmac_secret,
    hash_content,
    message_signature,
)


@ddt
class TestUtils(TestCase):
    def test_match_hmac_secret(self):
        hmac_secret, encrypted, enc_key, salt = aes_encrypt_hmac_secret()
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
            'hmac-sha512',
            '/6lk2bC3td2pofMQOdywLPTmYQM6MP3b5gmGm9azYz8SIac1lqmITl5zJ1NdUzykMg/w2k55Ib/EznURl67rUw==',
        ),
        (
            'hmac-sha384',
            'gYw6VAI5YA7ykdU5N1PSP/UCGLdN2znASixGZ5wlT0wbLGxnmahafTvbqWOIpCfB',
        ),
        ('hmac-sha256', 'O3SR3AFqwaCy4CNyQCyGH6+kWSlAh+fL4J9wTVgtkx8='),
    )
    @unpack
    def test_hash_content(
        self,
        digest='hmac-256',
        expected_b64hash='O3SR3AFqwaCy4CNyQCyGH6+kWSlAh+fL4J9wTVgtkx8',
    ):
        content = 'test_message'.encode('utf-8')
        calculated_b64hash = hash_content(digest, content)
        self.assertTrue(
            calculated_b64hash == expected_b64hash,
            f'Computed hash did not match expected for {digest}',
        )

    @data(
        ('hmac-sha512', 'ZaIJF7XWibQHwbbgx6qd5AIh78SB/+WPJIXFHYIqzs4='),
        (
            'hmac-sha256',
            'BsDXXZ895Ko1KhznDwBhRBS0+g+5X+KoZz1b3R7JUXhQ/5r0Q+pN+FfhlL88KRiL3ya2RNw6GETHbzolHcuXAw==',
        ),
    )
    @unpack
    def test_message_signature(
        self,
        digest='hmac-512',
        calculated_b64signature='ZaIJF7XWibQHwbbgx6qd5AIh78SB/+WPJIXFHYIqzs4=',
    ):
        secret = 'test_secret'.encode('utf-8').hex()
        message = 'test_message'
        calculated_b64signature = message_signature(message, secret, digest)
        self.assertTrue(
            calculated_b64signature == calculated_b64signature,
            f'Computed signature did not match expected for {digest}',
        )
