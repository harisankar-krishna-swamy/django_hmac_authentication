import base64
import datetime
from datetime import timezone

from django.conf import settings
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from django_hmac_authentication.client_utils import prepare_string_to_sign, sign_string
from django_hmac_authentication.exceptions import (
    DateFormatException,
    ExpiredKeyException,
    ExpiredRequestException,
    FutureRequestException,
    KeyDoesNotExistException,
    RevokedKeyException,
    SignatureVerificationException,
    UnsupportedHMACMethodException,
)
from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.server_utils import aes_decrypt_hmac_secret

auth_req_timeout = getattr(settings, 'HMAC_AUTH_REQUEST_TIMEOUT', 5)
failed_attempts_threshold = getattr(settings, 'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', -1)
hmac_expires_in = getattr(settings, 'HMAC_EXPIRES_IN', None)


class HMACAuthentication(authentication.BaseAuthentication):
    authentication_methods = {'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'}

    def parse_authorization_header(self, content):
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

    def compute_request_signature(self, request, auth_method, date_in, hmac_key):
        enc_secret = base64.b64decode(hmac_key.secret.encode('utf-8'))
        enc_salt = base64.b64decode(hmac_key.salt.encode('utf-8'))
        secret = aes_decrypt_hmac_secret(enc_secret, enc_salt)

        data = getattr(request, 'data', None)
        string_to_sign = prepare_string_to_sign(data, date_in, auth_method)
        computed_signature = sign_string(string_to_sign, secret, auth_method)
        return computed_signature

    def authenticate(self, request):
        request_meta = request.META
        auth_hdr = request_meta.get('HTTP_AUTHORIZATION')

        if not auth_hdr:
            return None

        auth_method, key, signature, date_in = self.parse_authorization_header(auth_hdr)

        if not auth_method or not key or not signature or not date_in:
            return None

        # auth header structure is for hmac authentication
        if auth_method not in self.authentication_methods:
            raise UnsupportedHMACMethodException(hmac_method=auth_method)

        utcnow = datetime.datetime.now(timezone.utc)

        try:
            req_utc = datetime.datetime.fromisoformat(date_in)
        except ValueError:
            raise DateFormatException()

        if req_utc >= utcnow:
            raise FutureRequestException()

        delta = utcnow - req_utc
        if delta.total_seconds() > auth_req_timeout:
            raise ExpiredRequestException()

        hmac_key = ApiHMACKey.objects.filter(id=key).first()
        if not hmac_key:
            raise KeyDoesNotExistException()

        if hmac_key.revoked:
            raise RevokedKeyException()

        if hmac_expires_in and (
            not hmac_key.expires_at or hmac_key.expires_at <= utcnow
        ):
            raise ExpiredKeyException()

        if not hmac_key.user.is_active:
            raise AuthenticationFailed('User is inactive')

        computed_signature = self.compute_request_signature(
            request, auth_method, date_in, hmac_key
        )
        if not computed_signature == signature:
            if failed_attempts_threshold > 0:
                self._revoke_key_on_failed_attempts(hmac_key)
            raise SignatureVerificationException()

        return hmac_key.user, None

    def _revoke_key_on_failed_attempts(self, hmac_key):
        # check db field max value
        failed_attempts = hmac_key.failed_attempts + 1
        if failed_attempts < 32767:
            hmac_key.failed_attempts = failed_attempts
            hmac_key.save()

        if hmac_key.failed_attempts >= failed_attempts_threshold:
            hmac_key.revoked = True
            hmac_key.save()
            raise SignatureVerificationException(
                'Signature verification failed. Too many failed attempts. Key revoked.'
            )
