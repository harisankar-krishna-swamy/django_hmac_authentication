from ddt import data, ddt, unpack
from rest_framework.test import APITestCase

from django_hmac_authentication.authentication import HMACAuthentication

test_data__authorization_header_parsing_invalid = (
    # invalid header structures for authorization header content
    (None, False),
    ('', False),
    ('method', False),
    ('method api_key', False),
    ('method api_key;signature', False),
)

test_data__authorization_header_parsing_valid = (
    # valid header structure
    ('method api_key;signature;date_in', True),
)


@ddt
class TestHMACAuthentication(APITestCase):
    def setUp(self) -> None:
        self.auth = HMACAuthentication()

    test_data__authorization_header_parsing = (
        *test_data__authorization_header_parsing_invalid,
        *test_data__authorization_header_parsing_valid,
    )

    @data(*test_data__authorization_header_parsing)
    @unpack
    def test_hmac_authentication_authorization_header_parsing(
        self, header=None, valid_header=False
    ):
        header_parts = self.auth.parse_authorization_header(header)
        for part in header_parts:
            if not valid_header:
                self.assertIsNone(
                    part,
                    f'Header parsing failed. Header part {part} when expecting None',
                )
            else:
                self.assertIsNotNone(
                    part,
                    f'Header parsing failed. Header part {part} cannot be None with valid header',
                )
