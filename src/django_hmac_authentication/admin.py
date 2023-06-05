# Register your models here.
from datetime import datetime, timezone

from django.contrib import admin

from django_hmac_authentication.models import ApiHMACKey


class AdminApiHMACKey(admin.ModelAdmin):
    list_per_page = 10
    list_display = (
        'user',
        'id',
        'deactivated',
        'expired',
        'created_at',
        'modified_on',
    )
    ordering = ('-created_at', 'user')
    search_fields = (
        'user',
        'id',
    )
    fields = ('created_at', 'modified_on', 'user', 'id', 'revoked', 'expires_at')
    readonly_fields = (
        'user',
        'id',
        'created_at',
        'modified_on',
        'expires_at',
    )

    @admin.display(description='active', boolean=True)
    def deactivated(self, obj):
        return not obj.revoked

    @admin.display(description='expired', boolean=True)
    def expired(self, obj):
        if not obj.expires_at:
            return False
        return obj.expires_at <= datetime.now(tz=timezone.utc)


admin.site.register(ApiHMACKey, AdminApiHMACKey)
