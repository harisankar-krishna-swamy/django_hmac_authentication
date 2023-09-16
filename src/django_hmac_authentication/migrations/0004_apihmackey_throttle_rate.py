# Generated by Django 4.1.7 on 2023-09-13 07:58

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("django_hmac_authentication", "0003_apihmackey_expires_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="apihmackey",
            name="throttle_rate",
            field=models.CharField(
                default="200/min",
                max_length=15,
                validators=[
                    django.core.validators.RegexValidator(
                        code="Invalid throttle rate",
                        message="Throttle rate must be of form number/unit. Examples: 100/second, 100/sec, 200/minute 200/min 500/day",
                        regex="^(\\d+)(\\/)(min|minute|day|second|sec)$",
                    )
                ],
                verbose_name="Throttle rate",
            ),
        ),
    ]
