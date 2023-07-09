from django.conf import settings
from django.core.cache import caches
from django.db.models.signals import post_save
from django.dispatch import receiver

from django_hmac_authentication.models import ApiHMACKey

hmac_cache_alias = getattr(settings, 'HMAC_CACHE_ALIAS', None)


@receiver(post_save, sender=ApiHMACKey)
def update_hmac_cache_on_save(sender, instance, created, **kwargs):
    if hmac_cache_alias:
        caches[hmac_cache_alias].set(f'ApiHMACKey.id.{instance.id}', instance)
