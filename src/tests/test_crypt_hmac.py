from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.hmac import (
    cipher_decrypt_hmac_secret,
    cipher_encrypted_hmac_secret,
)
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
)

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


@ddt
class TestCryptHmac(TestCase):
    def setUp(self):
        self.kd_password = 'test_kd_password'

    @data((CIPHER_AES_256,), (CIPHER_CAMELLIA_256,))
    @unpack
    def test__cipher_encrypt_decrypt_hmac_secret(self, cipher_algorithm='AES-256'):
        hmac_secret, encrypted, enc_key, salt = cipher_encrypted_hmac_secret(
            self.kd_password, cipher_algorithm
        )
        decrypted = cipher_decrypt_hmac_secret(
            encrypted, self.kd_password, salt, cipher_algorithm
        )
        self.assertTrue(
            hmac_secret == decrypted,
            f'Decrypted secret did not match original with cipher algorithm {cipher_algorithm}',
        )
