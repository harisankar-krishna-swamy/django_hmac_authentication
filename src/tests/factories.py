import base64
import secrets

import factory
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.db.models.signals import post_save
from factory.django import DjangoModelFactory

from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.server_utils import aes_encrypted_hmac_secret

user_model = get_user_model()
test_password = secrets.token_hex()
test_hmac_secret, test_encrypted, test_enc_key, test_salt = aes_encrypted_hmac_secret()


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
