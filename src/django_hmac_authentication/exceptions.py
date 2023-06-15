from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed


class UnsupportedHMACMethodException(AuthenticationFailed):
    default_detail = _('Unsupported hmac method "{hmac_method}".')
    default_code = 'hmac_method'

    def __init__(self, hmac_method, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail).format(hmac_method=hmac_method)
            super().__init__(detail, code)


class KeyDoesNotExistException(AuthenticationFailed):
    default_detail = _('Key does not exist.')
    default_code = 'key_unknown'


class RevokedKeyException(AuthenticationFailed):
    default_detail = _('Key revoked.')
    default_code = 'key_revoked'


class ExpiredRequestException(AuthenticationFailed):
    default_detail = _('Request has expired.')
    default_code = 'expired_request'


class FutureRequestException(AuthenticationFailed):
    default_detail = _('Request cannot be in future.')
    default_code = 'future_request'


class SignatureVerificationException(AuthenticationFailed):
    default_detail = _('Signature verification failed.')
    default_code = 'verification_failed'


class DateFormatException(AuthenticationFailed):
    default_detail = _('Invalid date format in Authorization header.')
    default_code = 'date_format'


class ExpiredKeyException(AuthenticationFailed):
    default_detail = _('Key has expired.')
    default_code = 'expired_key'
