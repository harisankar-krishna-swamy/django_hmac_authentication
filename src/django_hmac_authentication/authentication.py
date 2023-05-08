import base64
import datetime
from datetime import timezone

from django.conf import settings
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.utils import (
    aes_decrypt_hmac_secret,
    hash_content,
    message_signature,
)

auth_timeout = getattr(settings, 'HMAC_AUTH_REQUEST_TIMEOUT', 5)


class HMACAuthentication(authentication.BaseAuthentication):
    authentication_methods = {'hmac-sha512', 'hmac-sha384', 'hmac-sha256'}

    def parse_authorization_header(self, content):
        if not content:
            return None, None, None
        try:
            auth_method, rest = content.split()
            if (
                not auth_method
                or auth_method.lower() not in self.authentication_methods
                or not rest
            ):
                return None, None

            api_key, signature, dt = rest.split(';')
            if not api_key or not signature or not dt:
                return None, None

            return auth_method, api_key, signature, dt
        except (AttributeError, ValueError):
            return None, None

    def compute_request_signature(self, request, auth_method, date_in, api_secret):
        body_hash = hash_content(auth_method, request.body)
        to_hash = f'{body_hash};{date_in}'
        enc_secret = base64.b64decode(api_secret.secret.encode('utf-8'))
        enc_salt = base64.b64decode(api_secret.salt.encode('utf-8'))
        secret = aes_decrypt_hmac_secret(enc_secret, enc_salt)
        computed_signature = message_signature(to_hash, secret, auth_method)
        return computed_signature

    def authenticate(self, request):
        request_meta = request.META
        auth_hdr = request_meta.get('HTTP_AUTHORIZATION')

        if not auth_hdr:
            return None

        auth_method, key, signature, date_in = self.parse_authorization_header(auth_hdr)

        utcnow = datetime.datetime.now(timezone.utc)
        delta = utcnow - datetime.datetime.fromisoformat(date_in)
        if delta.total_seconds() > auth_timeout:
            raise AuthenticationFailed('Request timed out')

        api_secret = ApiHMACKey.objects.filter(id=key).first()
        if not api_secret or api_secret.revoked:
            raise AuthenticationFailed('Invalid API Key')

        if not api_secret.user.is_active:
            raise AuthenticationFailed('User is inactive')

        computed_signature = self.compute_request_signature(
            request, auth_method, date_in, api_secret
        )
        if not computed_signature == signature:
            raise AuthenticationFailed('Message verification failed')

        return api_secret.user, None
