import time

from django.core.cache import caches
from rest_framework.throttling import BaseThrottle

from django_hmac_authentication.server_utils import (
    get_api_hmac_key,
    parse_authorization_header,
)
from django_hmac_authentication.settings import setting_for


class HMACApiKeyRateThrottle(BaseThrottle):
    """
    Based on DRF SimpleRateThrottle. Limits the rate of API calls that may be made using a given HMAC API Key.
    The hmac key's id field will be used as a unique cache key.
    """

    def __init__(self):
        # set a default to bypass scope
        self.rate = '200/minute'
        self.cache = caches[setting_for('HMAC_CACHE_ALIAS')]

    def allow_request(self, request, view):

        auth_header = request.META.get('HTTP_AUTHORIZATION')
        auth_method, key_id, signature, date_in = parse_authorization_header(
            auth_header
        )

        hmac_key = get_api_hmac_key(key_id)
        if hmac_key:
            self.rate = hmac_key.throttle_rate

        self.num_requests, self.duration = self.parse_rate(self.rate)

        self.key = f'throttle_hmack_api_key_{key_id}'

        self.history = self.cache.get(self.key, [])
        self.now = time.time()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return False

        self.history.insert(0, self.now)
        self.cache.set(self.key, self.history, self.duration)
        return True

    def parse_rate(self, rate):
        if rate is None:
            return (None, None)
        num, period = rate.split('/')
        num_requests = int(num)
        duration = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[period[0]]
        return (num_requests, duration)

    def wait(self):
        """
        Returns the recommended next request time in seconds.
        """
        if self.history:
            remaining_duration = self.duration - (self.now - self.history[-1])
        else:
            remaining_duration = self.duration

        available_requests = self.num_requests - len(self.history) + 1
        if available_requests <= 0:
            return None

        return remaining_duration / float(available_requests)
