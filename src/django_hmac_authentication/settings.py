from datetime import timezone

from django.conf import settings

DEFAULTS = {
    'MAX_HMACS_PER_USER': 10,
    'HMAC_AUTH_REQUEST_TIMEOUT': 5,
    # Optional configs
    'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD': None,
    'HMAC_EXPIRES_IN': None,
    'HMAC_CACHE_ALIAS': None,
    'ENABLE_UTC': True,
}

NAMES = set(DEFAULTS.keys())


def setting_for(name: str):
    if name not in NAMES:
        raise AttributeError(f'Invalid setting name {name}')

    hmac_settings = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)

    if hmac_settings is None:
        hmac_settings = {}

    try:
        val = hmac_settings[name]
    except KeyError:
        val = DEFAULTS[name]

    return val


def get_tz():
    tz = timezone.utc if setting_for("ENABLE_UTC") else None

    return tz
