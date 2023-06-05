import json
from datetime import datetime, timezone
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from freezegun import freeze_time

from django_hmac_authentication.models import ApiHMACKey
from django_hmac_authentication.server_utils import timedelta_from_config
from tests.factories import ApiHMACKeyUserFactory


def call_mgmt_command(cmd: str, *args, **kwargs):
    out, err = StringIO(), StringIO()
    call_command(cmd, *args, stdout=out, stderr=err, **kwargs)
    return out.getvalue()


class TestMgmtCmdCreateHMACForUser(TestCase):
    """
    Tests management command create_dsat_for_user
    """

    def setUp(self) -> None:
        self.user = ApiHMACKeyUserFactory()
        self.cmd = 'create_hmac_for_user'

    def test_non_existing_user(self):
        out = call_mgmt_command(self.cmd, 'non_existing_user')
        self.assertIn('does not exist', out)
        self.assertNotIn('token_id', out)

    def test_existing_user__valid_hmac_count(self):
        out = call_mgmt_command(self.cmd, self.user)
        resp = json.loads(out)
        for field in ('api_key', 'api_secret', 'message'):
            self.assertIn(field, resp, f'Field {field} is missing in token response')
            self.assertIsNotNone(
                resp[field], f'Field {field} in token response cannot be None'
            )

    def test__max_hmac_per_user(self):
        from django.conf import settings

        for i in range(0, settings.MAX_HMACS_PER_USER + 1):
            out = call_mgmt_command(self.cmd, self.user)
            if i >= settings.MAX_HMACS_PER_USER:
                self.assertIn('Maximum API secrets limit reached for user', out)

    def test__expires_in(self):
        expires_in = '1h'
        initial_datetime = datetime.now(timezone.utc)
        with mock.patch(
            'django_hmac_authentication.server_utils.hmac_expires_in',
            expires_in,
        ):
            with freeze_time(initial_datetime):
                _ = call_mgmt_command(self.cmd, self.user)

        hmac = ApiHMACKey.objects.get(user=self.user)
        self.assertEqual(
            hmac.expires_at,
            initial_datetime + timedelta_from_config(expires_in),
            f'HMAC key expiry time did not match expected value for {expires_in}',
        )
