# Create your models here.
import uuid

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.fields import DateTimeField
from django.utils.translation import gettext_lazy as _

user_model = settings.AUTH_USER_MODEL

throttle_rate_validator = RegexValidator(
    regex=r'^(\d+)(\/)(min|minute|day|second|sec)$',
    message='Throttle rate must be formatted as a number/unit. Examples: 100/second, 100/sec, 200/minute 200/min, 500/day',
    code='Invalid throttle rate',
)


class ApiHMACKey(models.Model):
    created_at = DateTimeField(auto_now_add=True, db_index=True)
    modified_on = DateTimeField(auto_now=True, db_index=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(
        user_model, on_delete=models.CASCADE, related_name='api_hmac_keys'
    )
    secret = models.CharField(_('Secret'), max_length=512, null=False, editable=False)
    salt = models.CharField(_('Salt'), max_length=80, null=False, editable=False)
    revoked = models.BooleanField(_('Revoked'), default=False)
    failed_attempts = models.PositiveSmallIntegerField(
        _('Failed authentication attempts'), default=0, null=False, blank=False
    )
    expires_at = DateTimeField(
        _('Expires at'), default=None, null=True, db_index=True, editable=False
    )
    throttle_rate = models.CharField(
        _('Throttle rate'),
        max_length=15,
        null=False,
        blank=False,
        default='200/min',
        validators=[throttle_rate_validator],
    )
    cipher_algorithm = models.CharField(
        _('Cipher algorithm'),
        max_length=24,
        null=False,
        editable=False,
        default='AES-256',
    )

    def __str__(self):
        return f'{self.user}'

    class Meta:
        verbose_name = 'API HMAC Key'
        verbose_name_plural = 'API HMAC Keys'
