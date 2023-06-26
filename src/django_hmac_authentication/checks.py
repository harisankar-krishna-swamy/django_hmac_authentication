from django.conf import settings
from django.core.checks import Error


def check_configuration(**kwargs):
    from django_hmac_authentication.server_utils import timedelta_from_config

    errors = []

    # MAX_HMACS_PER_USER
    max_hmacs_per_user = getattr(settings, 'MAX_HMACS_PER_USER', None)
    if (
        max_hmacs_per_user is None
        or not type(max_hmacs_per_user) == int
        or max_hmacs_per_user <= 0
    ):
        errors.append(
            Error(
                f'MAX_HMACS_PER_USER must be an integer value greater than zero. Found {repr(max_hmacs_per_user)}.',
                hint='Set a positive value like 5, 10, 25, 50',
                obj=repr(max_hmacs_per_user),
                id='django_hmac_authentication.E001',
            )
        )

    # HMAC_AUTH_REQUEST_TIMEOUT
    hmac_auth_request_timeout = getattr(settings, 'HMAC_AUTH_REQUEST_TIMEOUT', None)
    if (
        hmac_auth_request_timeout is None
        or not type(hmac_auth_request_timeout) == int
        or hmac_auth_request_timeout <= 0
    ):
        errors.append(
            Error(
                f'If set, HMAC_AUTH_REQUEST_TIMEOUT must be an integer value greater than zero. Found {repr(hmac_auth_request_timeout)}.',
                hint='Set a positive value like 2, 3, 5 representing seconds earlier than which requests are rejected',
                obj=repr(hmac_auth_request_timeout),
                id='django_hmac_authentication.E002',
            )
        )

    # HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD
    hmac_auth_failed_attempts_threshold = getattr(
        settings, 'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', None
    )
    if hmac_auth_failed_attempts_threshold is not None and (
        not type(hmac_auth_failed_attempts_threshold) == int
        or hmac_auth_failed_attempts_threshold <= 0
    ):
        errors.append(
            Error(
                f'If set, HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD must be an integer value greater than zero. Found {repr(hmac_auth_failed_attempts_threshold)}.',
                hint='Set a positive value like 5, 10 or 15 for max failed attempts after which key is revoked',
                obj=repr(hmac_auth_failed_attempts_threshold),
                id='django_hmac_authentication.E003',
            )
        )

    # HMAC_EXPIRES_IN
    hmac_expires_in = getattr(settings, 'HMAC_EXPIRES_IN', None)
    try:
        timedelta_from_config(hmac_expires_in)
    except (TypeError, ValueError):
        errors.append(
            Error(
                f'If set, HMAC_EXPIRES_IN expire keys after interval in hours, minutes or seconds.  Found {repr(hmac_expires_in)}',
                hint="Example '1h', '5m', '3600s'",
                obj=repr(hmac_expires_in),
                id='django_hmac_authentication.E004',
            )
        )

    return errors
