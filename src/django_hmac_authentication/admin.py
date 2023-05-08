# Register your models here.

from django.contrib import admin

from django_hmac_authentication.models import ApiHMACKey


class AdminApiHMACKey(admin.ModelAdmin):
    list_per_page = 10
    list_display = (
        'user',
        'id',
        'deactivated',
        'created_at',
        'modified_on',
    )
    ordering = ('-created_at', 'user')
    search_fields = (
        'user',
        'id',
    )
    fields = ('created_at', 'modified_on', 'user', 'id', 'revoked')
    readonly_fields = (
        'user',
        'id',
        'created_at',
        'modified_on',
    )

    @admin.display(description='active', boolean=True)
    def deactivated(self, obj):
        return not obj.revoked


admin.site.register(ApiHMACKey, AdminApiHMACKey)
