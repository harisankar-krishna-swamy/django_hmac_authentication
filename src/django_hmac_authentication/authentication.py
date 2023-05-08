import base64
import datetime
import json
from datetime import timezone

from django.conf import settings
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from django_hmac_authentication.client_utils import hash_content, message_signature
from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.server_utils import aes_decrypt_hmac_secret

auth_timeout = getattr(settings, 'HMAC_AUTH_REQUEST_TIMEOUT', 5)


class HMACAuthentication(authentication.BaseAuthentication):
    authentication_methods = {'HMAC-SHA512', 'HMAC-SHA384', 'HMAC-SHA256'}

    def parse_authorization_header(self, content):
        if not content:
            return None, None, None
        try:
            auth_method, rest = content.split()
            if (
                not auth_method
                or auth_method not in self.authentication_methods
                or not rest
            ):
                return None, None

            api_key, signature, dt = rest.split(';')
            if not api_key or not signature or not dt:
                return None, None

            return auth_method, api_key, signature, dt
        except (AttributeError, ValueError):
            return None, None

    def compute_request_signature(self, request, auth_method, date_in, hmac_key):
        string_to_sign = f';{date_in}'
        data = getattr(request, 'data', None)
        body = json.dumps(data).encode('utf-8') if data else None
        body_hash = hash_content(auth_method, body)
        if body_hash:
            string_to_sign = f'{body_hash}' + string_to_sign
        enc_secret = base64.b64decode(hmac_key.secret.encode('utf-8'))
        enc_salt = base64.b64decode(hmac_key.salt.encode('utf-8'))
        secret = aes_decrypt_hmac_secret(enc_secret, enc_salt)
        computed_signature = message_signature(string_to_sign, secret, auth_method)
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

        hmac_key = ApiHMACKey.objects.filter(id=key).first()
        if not hmac_key or hmac_key.revoked:
            raise AuthenticationFailed('Invalid API Key')

        if not hmac_key.user.is_active:
            raise AuthenticationFailed('User is inactive')

        computed_signature = self.compute_request_signature(
            request, auth_method, date_in, hmac_key
        )
        if not computed_signature == signature:
            raise AuthenticationFailed('Message verification failed')

        return hmac_key.user, None
