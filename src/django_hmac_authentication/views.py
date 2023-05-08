from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response

from .serializers import ApiHMACKeyResponseSerializer
from .server_utils import create_shared_secret_for_user


class CreateApiHMACKey(ObtainAuthToken):
    """
    Create API access HMAC key and secret for user.
    """

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        api_key, api_secret = create_shared_secret_for_user(user)
        token_resp = ApiHMACKeyResponseSerializer(
            {'api_key': api_key, 'api_secret': api_secret}
        ).data
        return Response(token_resp)
