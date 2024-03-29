# Generated by Django 4.1.7 on 2023-12-14 09:12

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("django_hmac_authentication", "0004_apihmackey_throttle_rate"),
    ]

    operations = [
        migrations.AlterField(
            model_name="apihmackey",
            name="throttle_rate",
            field=models.CharField(
                default="200/min",
                max_length=15,
                validators=[
                    django.core.validators.RegexValidator(
                        code="Invalid throttle rate",
                        message="Throttle rate must be formatted as a number/unit. Examples: 100/second, 100/sec, 200/minute 200/min, 500/day",
                        regex="^(\\d+)(\\/)(min|minute|day|second|sec)$",
                    )
                ],
                verbose_name="Throttle rate",
            ),
        ),
    ]
