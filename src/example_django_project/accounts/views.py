from rest_framework.response import Response
from rest_framework.views import APIView


class AnAuthenticatedView(APIView):
    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)
