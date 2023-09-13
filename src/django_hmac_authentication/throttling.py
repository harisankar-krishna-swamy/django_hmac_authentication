from django.core.cache import caches
from rest_framework.throttling import SimpleRateThrottle

from django_hmac_authentication.server_utils import (
    get_api_hmac_key,
    parse_authorization_header,
)
from django_hmac_authentication.settings import setting_for

hmac_cache_alias = setting_for('HMAC_CACHE_ALIAS')


class HMACApiKeyRateThrottle(SimpleRateThrottle):
    """
    Limits the rate of API calls that may be made using a given HMAC API Key.
    The hmac key's id field will be used as a unique cache key if the user is
    authenticated.
    """

    cache = caches[hmac_cache_alias]
    scope = 'hmac_apikey'

    def allow_request(self, request, view):
        if self.rate is None:
            return True

        auth_header = request.META.get('HTTP_AUTHORIZATION')
        auth_method, key_id, signature, date_in = parse_authorization_header(
            auth_header
        )

        hmac_key = get_api_hmac_key(key_id)
        if hmac_key:
            self.rate = hmac_key.throttle_rate

        self.num_requests, self.duration = self.parse_rate(self.rate)

        self.key = self.cache_format % {'scope': self.scope, 'ident': key_id}

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return self.throttle_failure()
        return self.throttle_success()
