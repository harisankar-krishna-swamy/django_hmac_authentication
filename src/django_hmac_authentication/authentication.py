import base64
import datetime
from datetime import timezone

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
from django_hmac_authentication.server_utils import (
    check_key_for_kill_switch,
    cipher_decrypt_hmac_secret,
    get_api_hmac_key,
    parse_authorization_header,
)
from django_hmac_authentication.settings import setting_for

auth_req_timeout = setting_for('HMAC_AUTH_REQUEST_TIMEOUT')
failed_attempts_threshold = setting_for('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD')
hmac_expires_in = setting_for('HMAC_EXPIRES_IN')
hmac_kill_switch_on = setting_for('HMAC_KILL_SWITCH')


class HMACAuthentication(authentication.BaseAuthentication):
    authentication_methods = {'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'}

    def compute_request_signature(self, request, auth_method, date_in, hmac_key):
        enc_secret = base64.b64decode(hmac_key.secret.encode('utf-8'))
        enc_salt = base64.b64decode(hmac_key.salt.encode('utf-8'))
        secret = cipher_decrypt_hmac_secret(
            enc_secret, enc_salt, hmac_key.cipher_algorithm
        )

        data = getattr(request, 'data', None)
        string_to_sign = prepare_string_to_sign(data, date_in, auth_method)
        computed_signature = sign_string(string_to_sign, secret, auth_method)
        return computed_signature

    def authenticate(self, request):
        request_meta = request.META
        auth_hdr = request_meta.get('HTTP_AUTHORIZATION')

        if not auth_hdr:
            return None

        auth_method, key, signature, date_in = parse_authorization_header(auth_hdr)

        if hmac_kill_switch_on:
            check_key_for_kill_switch(key)

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

        hmac_key = get_api_hmac_key(key_id=key)

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
            if failed_attempts_threshold and failed_attempts_threshold > 0:
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
