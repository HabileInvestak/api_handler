# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('user_id', models.TextField()),
                ('apiName', models.TextField()),
                ('request_id', models.AutoField(unique=True, serialize=False, primary_key=True)),
                ('investak_request_time_stamp', models.DateTimeField(null=True)),
                ('api_request_time_stamp', models.DateTimeField(null=True)),
                ('tso_response_time_stamp', models.DateTimeField(null=True)),
                ('api_response_time_stamp', models.DateTimeField(null=True)),
                ('investak_request', models.TextField()),
                ('api_request', models.TextField()),
                ('tso_response', models.TextField()),
                ('api_response', models.TextField()),
                ('api_status', models.TextField()),
                ('tso_status', models.TextField()),
                ('ipAddress', models.TextField()),
            ],
            options={
                'ordering': ('request_id',),
            },
        ),
    ]