"""
WSGI config for rest_example project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
from api_handler_app.ExcelSheet import *
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api_handler.settings")
application = get_wsgi_application()
a = ExcelSheetApi()
i = ExcelSheetInput()
s = ExcelSheetSuccess()
f = ExcelSheetFailure()
j = ExcelSheetJson()
l = ExcelSheetLists()
ApiHomeDict = a.apiHomeDict()
InputDict = i.inputDict()
SuccessDict = s.successDict()
FailureDict = f.failureDict()
JsonDict = j.jsonDict()
ListDict = l.listDict()
ListOfDict=[ApiHomeDict,InputDict,SuccessDict,FailureDict,JsonDict,ListDict]

class ReturnAllDict:
    def returnDict(self):
        print "call Loading dictioanry from excel once deployment"
        return ListOfDict