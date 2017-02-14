from utils import UtilClass
from datetime import datetime

from api_handler_app.models import Audit

import logging

logger = logging.getLogger('api_handler_app.audit.py')

'''This class will store All the request and response to data base for audit purpose'''
class AuditTrial():
    
    '''This method will store the request and response InvestAK for audit purpose'''
    def investak_request_audit(self,userId,bodyContent,apiName,ApiHomeDict,ipAddress):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        requestId=''
        try:
            dateNow = datetime.now ()
            logging = ApiHomeDict.get(apiName)[0].logging
            logger.debug("Before Investak API audit enable")
            logger.debug("Logging="+logging)
            if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('INVESTAK_API_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                logger.debug("Investak API audit enable")
                Auditobj=Audit(user_id=userId, investak_request=bodyContent,investak_request_time_stamp=dateNow,apiName=apiName,ipAddress=ipAddress)
                Auditobj.save()
                requestId=Auditobj.request_id
                logger.debug("requestId="+str(requestId))
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return requestId
    

    '''This method will store the request of api for audit purpose'''
    def api_request_audit(self,requestId,request,apiName,userId,ApiHomeDict,ipAddress):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging=ApiHomeDict.get(apiName)[0].logging
            if(logging==utilClass.readProperty("YES") and utilClass.readProperty('API_TSO_AUDIT_ENABLE')==utilClass.readProperty("YES") and utilClass.readProperty('INVESTAK_API_AUDIT_ENABLE')==utilClass.readProperty("YES")):
                Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.readProperty('API_REQUEST'): request,utilClass.readProperty('API_REQUEST_TIME_STAMP'):dateNow,utilClass.readProperty('USER_ID'):userId},
                )
            else:
                Auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow,apiName=apiName,ipAddress=ipAddress)
                Auditobj.save ()
                requestId = Auditobj.request_id   
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return requestId
    
    
    '''This method will store the response of api for audit purpose'''
    def api_response_audit(self,requestId,request,apiName,ApiHomeDict,userId):
        utilClass=UtilClass()
        logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging = ApiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    print dict_var
                    stat=dict_var.get(utilClass.readProperty('STATUS'))
                    if stat == utilClass.readProperty ('OK'):
                        api_status = utilClass.readProperty('SUCCESS')
                        pass
                    else:
                        api_status = utilClass.readProperty('FAILURE')
                        break
                if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('INVESTAK_API_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.readProperty('API_RESPONSE'): request,utilClass.readProperty('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('API_STATUS'):api_status,utilClass.readProperty('USER_ID'):userId},
                ) 
            else:          
                stat= request.get (utilClass.readProperty('STATUS'))
                if stat== utilClass.readProperty ('OK'):
                    api_status=utilClass.readProperty ('SUCCESS')
                elif stat == utilClass.readProperty ('NOT_OK'):
                    api_status = utilClass.readProperty ('FAILURE')
                else:
                    api_status = utilClass.readProperty ('SUCCESS')
                if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('INVESTAK_API_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.readProperty('API_RESPONSE'): request,utilClass.readProperty('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('API_STATUS'):api_status,utilClass.readProperty('USER_ID'):userId},
                    )
            logger.info(utilClass.readProperty("EXITING_METHOD"))
        except Exception as e:
            raise e
    
    
    '''This method will store the response of tso for audit purpose'''
    def tso_response_audit(self,requestId,request,apiName,ApiHomeDict,SuccessDict,FailureDict):
        utilClass=UtilClass()
        logger.info(utilClass.readProperty("ENTERING_METHOD"))
        tso_status=''
        dictionary={}
        try:
            dateNow = datetime.now ()
            #find json array
            logging = ApiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    stat=dict_var.get(utilClass.readProperty('STATUS'))
                    if stat == utilClass.readProperty ('OK'):
                        tso_status = utilClass.readProperty('SUCCESS')
                        pass
                    else:
                        tso_status = utilClass.readProperty('FAILURE')
                        break
                if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('API_TSO_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.readProperty('TSO_RESPONSE'): request,utilClass.readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('TSO_STATUS'):tso_status},
                )    
            else:
                stat = request.get(utilClass.readProperty('STATUS'))
                if stat == utilClass.readProperty ('OK'):
                    tso_status = utilClass.readProperty('SUCCESS')
                    dictionary=SuccessDict
                elif stat == utilClass.readProperty ('NOT_OK'):
                    tso_status = utilClass.readProperty('FAILURE')
                    dictionary=FailureDict
                else:
                    tso_status=utilClass.readProperty('SUCCESS')
                    dictionary=SuccessDict
                logger.debug(apiName)
                logging = ApiHomeDict.get(apiName)[0].logging
                if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('API_TSO_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.readProperty('TSO_RESPONSE'): request,utilClass.readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('TSO_STATUS'):tso_status},
                    )
        except Exception as e:
            raise e
        logger.info(utilClass.readProperty("EXITING_METHOD"))
        return dictionary
