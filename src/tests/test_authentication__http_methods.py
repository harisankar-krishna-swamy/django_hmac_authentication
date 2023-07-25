from http import HTTPStatus

from ddt import data, ddt, unpack
from rest_framework.test import APIRequestFactory

from tests.testing_utils import TestHMACAuthenticationBase

test_data__hmac_http_methods = (
    # hmac-sha512
    (
        'HMAC-SHA512',
        'GET',
    ),
    (
        'HMAC-SHA512',
        'POST',
    ),
    (
        'HMAC-SHA512',
        'PATCH',
    ),
    (
        'HMAC-SHA512',
        'PUT',
    ),
    (
        'HMAC-SHA512',
        'DELETE',
    ),
    # hmac-sha384
    (
        'HMAC-SHA384',
        'GET',
    ),
    (
        'HMAC-SHA384',
        'POST',
    ),
    (
        'HMAC-SHA384',
        'PATCH',
    ),
    (
        'HMAC-SHA384',
        'PUT',
    ),
    (
        'HMAC-SHA384',
        'DELETE',
    ),
    # hmac-sha256
    (
        'HMAC-SHA256',
        'GET',
    ),
    (
        'HMAC-SHA256',
        'POST',
    ),
    (
        'HMAC-SHA256',
        'PATCH',
    ),
    (
        'HMAC-SHA256',
        'PUT',
    ),
    (
        'HMAC-SHA256',
        'DELETE',
    ),
)


@ddt
class TestHttpMethods(TestHMACAuthenticationBase):
    @data(*test_data__hmac_http_methods)
    @unpack
    def test_api__hmac_authenticate__valid(
        self, digest='HMAC-SHA512', http_method='POST'
    ):
        factory = APIRequestFactory()
        req_data = None
        if http_method in {'PUT', 'POST', 'PATCH'}:
            req_data = {'a': 1, 'b': 2}

        signature, utc_8601 = self._request_auth_header_fields(req_data, digest)

        headers = {
            f'{self.auth_header}': f'{digest} {self.hmac_key.id};{signature};{utc_8601}',
        }
        if http_method == 'GET':
            request = factory.get('/', data=None, **headers)

        if http_method == 'PUT':
            request = factory.put('/', data=req_data, format='json', **headers)
        if http_method == 'POST':
            request = factory.post('/', data=req_data, format='json', **headers)
        if http_method == 'PATCH':
            request = factory.patch('/', data=req_data, format='json', **headers)
        if http_method == 'DELETE':
            request = factory.delete('/', data=None, **headers)

        response = self.view(request)
        self.assertEqual(
            response.status_code,
            HTTPStatus.OK,
            f'Authentication failed with digest {digest} http_method {http_method}',
        )
