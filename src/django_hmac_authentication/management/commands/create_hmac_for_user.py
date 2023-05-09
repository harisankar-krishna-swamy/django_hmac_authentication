import json

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand
from django.db import transaction
from rest_framework.exceptions import ValidationError

from django_hmac_authentication.serializers import ApiHMACKeyResponseSerializer
from django_hmac_authentication.server_utils import create_shared_secret_for_user

user_model = get_user_model()


class Command(BaseCommand):
    help = "Create an HMAC key and secret for user"

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)

    @transaction.atomic
    def handle(self, *args, **options):
        username = options['username']
        try:
            user = user_model.objects.get(username=username)
            api_key, api_secret = create_shared_secret_for_user(user)
            resp = ApiHMACKeyResponseSerializer(
                {'api_key': api_key, 'api_secret': api_secret}
            ).data
            self.stdout.write(self.style.SUCCESS(json.dumps(resp)))
        except ValidationError as ve:
            self.stdout.write(self.style.ERROR(f'{ve}'))
        except ObjectDoesNotExist:
            self.stdout.write(self.style.ERROR(f'Username {username} does not exist'))
