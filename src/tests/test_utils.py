import os

from django.test import TestCase

from django_hmac_authentication.aes import aes_crypt
from django_hmac_authentication.utils import (
    aes_decrypt_hmac_secret,
    aes_encrypt_hmac_secret,
)


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
