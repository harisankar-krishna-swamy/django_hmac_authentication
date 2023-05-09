from rest_framework.response import Response
from rest_framework.views import APIView


class AnAuthenticatedView(APIView):
    def common_response(self):
        content = {'message': 'Hello, World!'}
        return Response(content)

    def get(self, request):
        return self.common_response()

    def post(self, request):
        return self.common_response()

    def patch(self, request):
        return self.common_response()

    def put(self, request):
        return self.common_response()

    def delete(self, request):
        return self.common_response()
