"""
WSGI config for rest_example project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

from api_handler_app.excel_sheet import *#ExcelSheetApi,ExcelSheetInput,ExcelSheetSuccess,ExcelSheetFailure,ExcelSheetJson,ExcelSheetLists


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api_handler.settings")
application = get_wsgi_application()
a = ExcelSheetApi()
i = ExcelSheetInput()
s = ExcelSheetSuccess()
f = ExcelSheetFailure()
j = ExcelSheetJson()
l = ExcelSheetLists()
apiHomeDict = a.api_home_dict()
inputDict = i.input_dict()
successDict = s.success_dict()
failureDict = f.failure_dict()
jsonDict = j.json_dict()
listDict = l.list_dict()
listOfDict=[apiHomeDict,inputDict,successDict,failureDict,jsonDict,listDict]
print "call Loading dictioanry from excel once deployment"



'''This class is used to read All excel sheet to return as a list'''
class ReturnAllDict:
    
    '''This method is used to read All excel sheet to return as a list'''
    def return_dict(self):
        print "call Loading dictioanry from excel once deployment"
        return listOfDict