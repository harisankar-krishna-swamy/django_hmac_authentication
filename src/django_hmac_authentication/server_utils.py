import base64
import os
import random
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from hashlib import pbkdf2_hmac

from django.conf import settings
from django.core.cache import caches
from rest_framework.exceptions import ValidationError

from django_hmac_authentication.crypt.aes import aes_crypt
from django_hmac_authentication.crypt.camellia import camellia_crypt
from django_hmac_authentication.crypt.settings import (
    CIPHER_AES_256,
    CIPHER_CAMELLIA_256,
    SUPPORTED_CIPHERS,
)
from django_hmac_authentication.exceptions import KeyKillSwitchException
from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.settings import setting_for

encoding = 'utf-8'
hash_func = 'sha256'

user_model = settings.AUTH_USER_MODEL
max_hmacs_per_user = setting_for('MAX_HMACS_PER_USER')

hmac_expires_in = setting_for('HMAC_EXPIRES_IN')
expires_in_units = ('h', 'm', 's')
expires_in_config_err = 'expires_in config must be string. Example: 4h, 5m, 3600s etc'

hmac_cache_alias = setting_for('HMAC_CACHE_ALIAS')

cipher_crypt_map = {CIPHER_AES_256: aes_crypt, CIPHER_CAMELLIA_256: camellia_crypt}


def cipher_encrypted_hmac_secret(cipher_algorithm=CIPHER_AES_256) -> tuple:
    salt = os.urandom(24)
    iv = salt[-16:]
    enc_key = pbkdf2_hmac(hash_func, settings.SECRET_KEY.encode(encoding), salt, 1000)

    hmac_secret = secrets.token_bytes(32)
    encrypted = cipher_crypt_map[cipher_algorithm](hmac_secret, enc_key, iv)

    return hmac_secret, encrypted, enc_key, salt


@lru_cache(maxsize=100)
def cipher_decrypt_hmac_secret(
    encrypted: bytes, salt: bytes, cipher_algorithm=CIPHER_AES_256
) -> bytes:
    enc_key = pbkdf2_hmac(hash_func, settings.SECRET_KEY.encode(encoding), salt, 1000)
    return cipher_crypt_map[cipher_algorithm](encrypted, enc_key, salt[-16:], False)


def create_shared_secret_for_user(user: user_model):
    expires_at = None
    if hmac_expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta_from_config(hmac_expires_in)

    n_user_hmacs = ApiHMACKey.objects.filter(user=user).count()
    if n_user_hmacs >= max_hmacs_per_user:
        raise ValidationError('Maximum API secrets limit reached for user')

    cipher_index = random.randint(0, len(SUPPORTED_CIPHERS) - 1)
    cipher_algorithm = SUPPORTED_CIPHERS[cipher_index]
    hmac_secret, encrypted, enc_key, salt = cipher_encrypted_hmac_secret(
        cipher_algorithm
    )
    hmac_key = ApiHMACKey(
        user=user,
        secret=base64.b64encode(encrypted).decode('utf-8'),
        salt=base64.b64encode(salt).decode('utf-8'),
        expires_at=expires_at,
        cipher_algorithm=cipher_algorithm,
    )
    hmac_key.save()
    return hmac_key.id, base64.b64encode(hmac_secret).decode('utf-8')


def timedelta_from_config(expires_in: str):

    if not expires_in or not isinstance(expires_in, str) or not len(expires_in) >= 2:
        raise TypeError(expires_in_config_err)

    value, unit = expires_in[0:-1], expires_in[-1:]
    if not value.isdigit() or not len(unit) == 1 or unit not in expires_in_units:
        raise ValueError(expires_in_config_err)

    value = int(value)
    if value == 0:
        raise ValueError(expires_in_config_err)

    if unit == 'h':
        return timedelta(hours=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    else:
        return timedelta(seconds=value)


def get_api_hmac_key(key_id):
    cache_key = f'ApiHMACKey.id.{key_id}'
    if hmac_cache_alias:
        hmac_key = caches[hmac_cache_alias].get(cache_key)
        if not hmac_key:
            hmac_key = ApiHMACKey.objects.filter(id=key_id).first()
            caches[hmac_cache_alias].set(cache_key, hmac_key)

        return hmac_key
    else:
        return ApiHMACKey.objects.filter(id=key_id).first()


def check_key_for_kill_switch(key_id):
    if not key_id:
        return
    switched_on = caches[hmac_cache_alias].get(f'HMAC_KILL_SWITCH__{key_id}')
    if switched_on:
        raise KeyKillSwitchException()


@lru_cache(maxsize=100)
def parse_authorization_header(content):
    if not content:
        return None, None, None, None
    try:
        auth_method, rest = content.split()
        if not auth_method or not rest:
            return None, None, None, None

        api_key, signature, dt = rest.split(';')
        if not api_key or not signature or not dt:
            return None, None, None, None

        return auth_method, api_key, signature, dt
    except (AttributeError, ValueError):
        return None, None, None, None
