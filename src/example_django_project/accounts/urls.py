from django.urls import path

from .views import AnAuthenticatedView

app_name = 'example-accounts'

urlpatterns = [
    # create token
    path(
        'an-authenticated-view/',
        AnAuthenticatedView.as_view(),
        name='an-authenticated-view',
    ),
]
