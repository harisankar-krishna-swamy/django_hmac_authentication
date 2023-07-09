from ddt import data, ddt, unpack
from django.test import TestCase

from django_hmac_authentication.checks import check_configuration


@ddt
class TestChecks(TestCase):

    test_data__settings = (
        # MAX_HMACS_PER_USER
        ('MAX_HMACS_PER_USER', None, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', 0, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', -1, 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', '5', 'django_hmac_authentication.E001'),
        ('MAX_HMACS_PER_USER', 5, None),
        # HMAC_AUTH_REQUEST_TIMEOUT
        ('HMAC_AUTH_REQUEST_TIMEOUT', None, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', 0, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', -1, 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', '5', 'django_hmac_authentication.E002'),
        ('HMAC_AUTH_REQUEST_TIMEOUT', 5, None),
        # HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', 0, 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', -1, 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', '5', 'django_hmac_authentication.E003'),
        ('HMAC_AUTH_FAILED_ATTEMPTS_THRESHOLD', 5, None),
        # HMAC_EXPIRES_IN
        ('HMAC_EXPIRES_IN', None, None),
        ('HMAC_EXPIRES_IN', 5, 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5', 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5g', 'django_hmac_authentication.E004'),
        ('HMAC_EXPIRES_IN', '5m', None),
        # HMAC_CACHE_ALIAS
        ('HMAC_CACHE_ALIAS', None, None),
        ('HMAC_CACHE_ALIAS', 'hmac_cache', 'django_hmac_authentication.E005'),
    )

    @data(*test_data__settings)
    @unpack
    def test_configuration(
        self,
        name='MAX_HMACS_PER_USER',
        value=0,
        error_id='django_hmac_authentication.E001',
    ):
        from django.conf import settings

        orig_value = getattr(settings, name, None)
        setattr(settings, name, value)
        errors = check_configuration()
        if not error_id:
            self.assertTrue(
                len(errors) == 0, f'Valid config {name} = {value} must not raise errors'
            )
        else:
            self.assertEqual(
                errors[-1].id,
                error_id,
                f'Incorrect config {name} = {value} must raise errors',
            )
        setattr(settings, name, orig_value)
