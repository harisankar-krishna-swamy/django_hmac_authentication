from django.test import TestCase

from django_hmac_authentication.settings import DEFAULTS, setting_for


class TestSettings(TestCase):
    def _confirm_settings(self, expected):
        for name in DEFAULTS.keys():
            self.assertEqual(setting_for(name), expected[name])

    def test_defaults__settings_None(self):
        from django.conf import settings

        orig_value = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)

        self._confirm_settings(DEFAULTS)

        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)

    def test_defaults__settings_empty(self):
        from django.conf import settings

        orig_value = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', {})

        self._confirm_settings(DEFAULTS)

        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)

    def test_defaults__settings_override(self):
        from django.conf import settings

        orig_value = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        overrides = {
            'MAX_HMACS_PER_USER': 100,
            'HMAC_AUTH_REQUEST_TIMEOUT': 50,
            'HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD': 10,
            'HMAC_EXPIRES_IN': '2h',
            'HMAC_CACHE_ALIAS': 'alias',
            'HMAC_KILL_SWITCH': True,
        }
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', overrides)

        self._confirm_settings(overrides)

        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)
