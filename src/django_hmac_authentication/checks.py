from django.conf import settings
from django.core.checks import Error


def check_configuration(**kwargs):
    from django.conf import settings as django_settings

    from django_hmac_authentication.server_utils import timedelta_from_config
    from django_hmac_authentication.settings import setting_for

    errors = []

    # MAX_HMACS_PER_USER
    max_hmacs_per_user = setting_for('MAX_HMACS_PER_USER')
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
    hmac_auth_request_timeout = setting_for('HMAC_AUTH_REQUEST_TIMEOUT')
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
    hmac_auth_failed_attempts_threshold = setting_for(
        'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD'
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
    hmac_expires_in = setting_for('HMAC_EXPIRES_IN')
    if hmac_expires_in:
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

    # HMAC_CACHE_ALIAS
    hmac_cache_alias = setting_for('HMAC_CACHE_ALIAS')
    if hmac_cache_alias and hmac_cache_alias not in settings.CACHES:
        errors.append(
            Error(
                f'Missing entry in settings.py CACHES for HMAC_CACHE_ALIAS "{hmac_cache_alias}"',
                hint="See https://docs.djangoproject.com/en/4.2/ref/settings/#caches",
                obj=repr(hmac_cache_alias),
                id='django_hmac_authentication.E005',
            )
        )

    # Check HMAC_AUTHENTICATION_SETTINGS in settings.py
    auth_settings = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
    if not auth_settings:
        errors.append(
            Error(
                'Missing HMAC_AUTHENTICATION_SETTINGS in settings.py',
                hint="https://github.com/harisankar-krishna-swamy/django_hmac_authentication#2-configuration",
                obj=repr(auth_settings),
                id='django_hmac_authentication.E006',
            )
        )

    # Check HMAC_KILL_SWITCH
    kill_switch_on = setting_for('HMAC_KILL_SWITCH')
    if kill_switch_on:
        if not hmac_cache_alias and hmac_cache_alias not in settings.CACHES:
            errors.append(
                Error(
                    'HMAC_KILL_SWITCH is enabled. HMAC_CACHE_ALIAS must be configured for kill switch feature',
                    hint="Set HMAC_CACHE_ALIAS to a cache in settings.py CACHES",
                    obj=repr(kill_switch_on),
                    id='django_hmac_authentication.E007',
                )
            )

    # if throttling is added then HMAC_CACHE_ALIAS must be set
    drf_settings = django_settings.REST_FRAMEWORK
    throttle_classes = drf_settings.get('DEFAULT_THROTTLE_CLASSES')
    throttle_enabled = throttle_classes and any(
        'HMACApiKeyRateThrottle' in tc for tc in throttle_classes
    )
    if throttle_enabled:
        if not hmac_cache_alias:
            errors.append(
                Error(
                    '"HMAC_CACHE_ALIAS" must be configured for throttling on hmac api keys',
                    hint="Set HMAC_CACHE_ALIAS in HMAC_AUTHENTICATION_SETTINGS to a valid cache in settings.py CACHES",
                    obj=repr('HMAC_CACHE_ALIAS'),
                    id='django_hmac_authentication.E008',
                )
            )
    return errors
