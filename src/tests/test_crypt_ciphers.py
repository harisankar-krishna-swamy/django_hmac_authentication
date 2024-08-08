import os

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
)

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


@ddt
class TestCryptCiphers(TestCase):
    @data((CIPHER_AES_256,), (CIPHER_CAMELLIA_256,))
    @unpack
    def test_cipher_crypt(self, cipher_algorithm=CIPHER_AES_256):
        msg = 'test_message'.encode('utf-8')
        key = os.urandom(32)
        iv = os.urandom(16)

        encrypted = cipher_crypt_map[cipher_algorithm](msg, key, iv, encrypt=True)
        decrypted = cipher_crypt_map[cipher_algorithm](
            encrypted, key, iv, encrypt=False
        )
        self.assertTrue(
            msg == decrypted,
            f'{cipher_algorithm} decrypted message did not match original',
        )
