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
                ('api_name', models.TextField()),
                ('request_id', models.AutoField(unique=True, serialize=False, primary_key=True)),
                ('source_request_time_stamp', models.DateTimeField(null=True)),
                ('request_validate_time_stamp', models.DateTimeField(null=True)),
                ('target_transmit_time_stamp', models.DateTimeField(null=True)),
                ('target_response_time_stamp', models.DateTimeField(null=True)),
                ('response_validate_time_stamp', models.DateTimeField(null=True)),
                ('source_transmit_time_stamp', models.DateTimeField(null=True)),
                ('source_request', models.TextField()),
                ('target_transmit', models.TextField()),
                ('target_response', models.TextField()),
                ('source_transmit', models.TextField()),
                ('source_request_status', models.TextField()),
                ('target_transmit_status', models.TextField()),
                ('target_response_status', models.TextField()),
                ('source_transmit_status', models.TextField()),
                ('ip_address', models.TextField()),
                ('source_system_name', models.TextField()),
                ('target_system_name', models.TextField()),
            ],
            options={
                'ordering': ('request_id',),
            },
        ),
    ]
