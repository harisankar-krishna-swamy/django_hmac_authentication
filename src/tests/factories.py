import base64
import secrets
from datetime import datetime, timedelta, timezone

import factory
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.db.models.signals import post_save
from factory.django import DjangoModelFactory
from vevde_security_utils.crypt.hmac import cipher_encrypted_hmac_secret
from vevde_security_utils.crypt.settings import CIPHER_AES_256

from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.settings import setting_for

hmac_kd_password = setting_for('HMAC_KD_PASSWORD')

user_model = get_user_model()
test_password = secrets.token_hex()
(
    test_hmac_secret,
    test_encrypted,
    test_enc_key,
    test_salt,
) = cipher_encrypted_hmac_secret(hmac_kd_password, CIPHER_AES_256)


@factory.django.mute_signals(post_save)
class SuperUserFactory(DjangoModelFactory):
    class Meta:
        model = user_model

    username = factory.Faker('email')
    password = factory.LazyFunction(lambda: make_password(test_password))
    is_staff = True
    is_active = True
    is_superuser = True


@factory.django.mute_signals(post_save)
class ApiHMACKeyUserFactory(DjangoModelFactory):
    class Meta:
        model = user_model

    username = factory.Faker('email')
    password = factory.LazyFunction(lambda: make_password(test_password))
    is_staff = False
    is_active = True
    is_superuser = False


class ApiHMACKeyFactory(DjangoModelFactory):
    class Meta:
        model = ApiHMACKey

    user = factory.SubFactory(SuperUserFactory)
    salt = base64.b64encode(test_salt).decode('utf-8')
    secret = base64.b64encode(test_encrypted).decode('utf-8')
    revoked = False
    failed_attempts = 0
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    throttle_rate = '1/day'
    cipher_algorithm = CIPHER_AES_256


class ApiHMACKeyWithMaxFailedAttemptsFactory(ApiHMACKeyFactory):
    class Meta:
        model = ApiHMACKey

    failed_attempts = 9999
