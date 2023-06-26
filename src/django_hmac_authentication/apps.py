from django.apps import AppConfig
from django.core import checks
from django.utils.translation import gettext_lazy as _

from django_hmac_authentication.checks import check_configuration


class DjangoHMACAuthenticationConfig(AppConfig):
    name = "django_hmac_authentication"
    verbose_name = _("Django HMAC Authentication")

    def ready(self):
        checks.register(check_configuration)
