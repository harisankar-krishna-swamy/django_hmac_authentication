import json
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

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

    def test_view__max_hmac_per_user(self):
        from django.conf import settings

        for i in range(0, settings.MAX_HMACS_PER_USER + 1):
            out = call_mgmt_command(self.cmd, self.user)
            if i >= settings.MAX_HMACS_PER_USER:
                self.assertIn('Maximum API secrets limit reached for user', out)
