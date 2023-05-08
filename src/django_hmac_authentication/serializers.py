from rest_framework import serializers


class ApiHMACKeyResponseSerializer(serializers.Serializer):
    api_key = serializers.CharField()
    api_secret = serializers.CharField()
    message = serializers.CharField(
        default='These credentials will be lost forever if not stored now'
    )
