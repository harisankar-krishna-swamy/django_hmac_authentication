import os
import secrets
from hashlib import pbkdf2_hmac

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
)

encoding = 'utf-8'
hash_func = 'sha256'
cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


def cipher_encrypted_hmac_secret(
    kd_password: str, cipher_algorithm=CIPHER_AES_256
) -> tuple:
    salt = os.urandom(24)
    iv = salt[-16:]
    enc_key = pbkdf2_hmac(hash_func, kd_password.encode(encoding), salt, 1000)

    hmac_secret = secrets.token_bytes(32)
    encrypted = cipher_crypt_map[cipher_algorithm](hmac_secret, enc_key, iv)

    return hmac_secret, encrypted, enc_key, salt


def cipher_decrypt_hmac_secret(
    encrypted: bytes, kd_password: str, salt: bytes, cipher_algorithm=CIPHER_AES_256
) -> bytes:
    enc_key = pbkdf2_hmac(hash_func, kd_password.encode(encoding), salt, 1000)
    return cipher_crypt_map[cipher_algorithm](encrypted, enc_key, salt[-16:], False)
