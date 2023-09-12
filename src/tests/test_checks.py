import copy

from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.checks import check_configuration
from django_hmac_authentication.settings import DEFAULTS


@ddt
class TestChecks(TestCase):
    def test__namespaced_settings(self):
        from django.conf import settings

        name = 'HMAC_AUTHENTICATION_SETTINGS'
        orig_value = getattr(settings, name, None)
        delattr(settings, name)
        errors = check_configuration()
        self.assertEqual(
            errors[-1].id,
            'django_hmac_authentication.E006',
            f'Missing {name} in settings.py must raise errors',
        )
        setattr(settings, name, orig_value)

    def _test_configuration(self, updates, error_id):
        from django.conf import settings

        hmac_settings = copy.deepcopy(DEFAULTS)
        hmac_settings.update(updates)
        orig_value = getattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', None)
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', hmac_settings)
        errors = check_configuration()
        if not error_id:
            self.assertTrue(
                len(errors) == 0, f'Valid config {updates} must not raise errors'
            )
        else:
            self.assertEqual(
                errors[-1].id,
                error_id,
                f'Incorrect config {updates} must raise errors',
            )
        setattr(settings, 'HMAC_AUTHENTICATION_SETTINGS', orig_value)

    @data(
        ('MAX_HMACS_PER_USER', None, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', 0, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', -1, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', '5', 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', 5, None),
    )
    @unpack
    def test_configuration__MAX_HMACS_PER_USER(
        self,
        name='MAX_HMACS_PER_USER',
        value=0,
        error_id='django_hmac_authentication.E001',
    ):
        self._test_configuration({name: value}, error_id)

    @data(
        ('HMAC_AUTH_REQUEST_TIMEOUT', None, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', 0, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', -1, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', '5', 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', 5, None),
    )
    @unpack
    def test_configuration__HMAC_AUTH_REQUEST_TIMEOUT(
        self,
        name='HMAC_AUTH_REQUEST_TIMEOUT',
        value=None,
        error_id='django_hmac_authentication.E002',
    ):
        self._test_configuration({name: value}, error_id)

    @data(
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', 0, 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', -1, 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', '5', 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', 5, None),
    )
    @unpack
    def test_configuration__HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD(
        self,
        name='HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD',
        value=0,
        error_id='django_hmac_authentication.E003',
    ):
        self._test_configuration({name: value}, error_id)

    @data(
        ('HMAC_EXPIRES_IN', None, None),
        ('HMAC_EXPIRES_IN', 5, 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5', 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5g', 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5m', None),
    )
    @unpack
    def test_configuration__HMAC_EXPIRES_IN(
        self,
        name='HMAC_EXPIRES_IN',
        value=None,
        error_id=None,
    ):
        self._test_configuration({name: value}, error_id)

    @data(
        ('HMAC_CACHE_ALIAS', None, None),
        ('HMAC_CACHE_ALIAS', 'hmac_cache', 'django_hmac_authentication.E005'),
    )
    @unpack
    def test_configuration__HMAC_CACHE_ALIAS(
        self,
        name='HMAC_CACHE_ALIAS',
        value=None,
        error_id=None,
    ):
        self._test_configuration({name: value}, error_id)

    @data(
        ('HMAC_KILL_SWITCH', None, None),
        ('HMAC_KILL_SWITCH', True, 'django_hmac_authentication.E007'),
    )
    @unpack
    def test_configuration__HMAC_KILL_SWITCH(
        self,
        name='HMAC_KILL_SWITCH',
        value=None,
        error_id=None,
    ):
        self._test_configuration({name: value}, error_id)

    def test_configuration__HMAC_KILL_SWITCH__with__HMAC_CACHE_ALIAS(self):
        self._test_configuration(
            {'HMAC_KILL_SWITCH': True, 'HMAC_CACHE_ALIAS': 'default'}, None
        )
