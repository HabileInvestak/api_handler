"""
WSGI config for rest_example project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

from api_handler_app.return_all_dict import ReturnAllDict


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api_handler.settings")
application = get_wsgi_application()

'''This is used to initially call for read all excel sheet with property file to store as a list,
we will use this list which contains all excel sheets for validation when apiName is call'''
ReturnAllDict().update_excel_property()


