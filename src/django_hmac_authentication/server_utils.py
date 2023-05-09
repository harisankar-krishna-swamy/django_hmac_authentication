import base64
import os
import secrets
from hashlib import pbkdf2_hmac

from django.conf import settings
from rest_framework.exceptions import ValidationError

from django_hmac_authentication.aes import aes_crypt
from django_hmac_authentication.models import ApiHMACKey

encoding = 'utf-8'
hash_func = 'sha256'

user_model = settings.AUTH_USER_MODEL
max_hmacs_per_user = getattr(settings, 'MAX_HMACS_PER_USER', 10)


def aes_encrypted_hmac_secret() -> tuple:
    salt = os.urandom(24)
    iv = salt[-16:]
    enc_key = pbkdf2_hmac(hash_func, settings.SECRET_KEY.encode(encoding), salt, 1000)

    hmac_secret = secrets.token_bytes(32)
    encrypted = aes_crypt(hmac_secret, enc_key, iv)
    return hmac_secret, encrypted, enc_key, salt


def aes_decrypt_hmac_secret(encrypted: bytes, salt: bytes) -> bytes:
    enc_key = pbkdf2_hmac(hash_func, settings.SECRET_KEY.encode(encoding), salt, 1000)
    return aes_crypt(encrypted, enc_key, salt[-16:], False)


def create_shared_secret_for_user(user: user_model):
    n_user_hmacs = ApiHMACKey.objects.filter(user=user).count()
    if n_user_hmacs >= max_hmacs_per_user:
        raise ValidationError('Maximum API secrets limit reached for user')
    hmac_secret, encrypted, enc_key, salt = aes_encrypted_hmac_secret()
    hmac_key = ApiHMACKey(
        user=user,
        secret=base64.b64encode(encrypted).decode('utf-8'),
        salt=base64.b64encode(salt).decode('utf-8'),
    )
    hmac_key.save()
    return hmac_key.id, base64.b64encode(hmac_secret).decode('utf-8')
