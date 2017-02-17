from datetime import datetime
import logging

from api_handler_app.models import Audit
from utils import UtilClass


logger = logging.getLogger('api_handler_app.audit.py')

'''This class will store All the request and response to data base for audit purpose'''
class AuditTrial():
    
    '''This method will store the request and response InvestAK for audit purpose'''
    def investak_request_audit(self,userId,bodyContent,apiName,apiHomeDict,ipAddress):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        requestId=''
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            logger.debug("Before Investak API audit enable")
            logger.debug("Logging="+logging)
            if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                logger.debug("Investak API audit enable")
                auditobj=Audit(user_id=userId, investak_request=bodyContent,investak_request_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress)
                auditobj.save()
                requestId=auditobj.request_id
                logger.debug("requestId="+str(requestId))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return requestId
    

    '''This method will store the request of api for audit purpose'''
    def api_request_audit(self,requestId,request,apiName,userId,apiHomeDict,ipAddress):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging=apiHomeDict.get(apiName)[0].logging
            if(logging==utilClass.read_property("YES") and utilClass.read_property('API_TSO_AUDIT_ENABLE')==utilClass.read_property("YES") and utilClass.read_property('INVESTAK_API_AUDIT_ENABLE')==utilClass.read_property("YES")):
                Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.read_property('API_REQUEST'): request,utilClass.read_property('API_REQUEST_TIME_STAMP'):dateNow,utilClass.read_property('USER_ID'):userId},
                )
            else:
                auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress)
                auditobj.save ()
                requestId = auditobj.request_id   
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return requestId
    
    
    '''This method will store the response of api for audit purpose'''
    def api_response_audit(self,requestId,request,apiName,apiHomeDict,userId):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    print dict_var
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        apiStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        apiStatus = utilClass.read_property('FAILURE')
                        break
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('API_RESPONSE'): request,utilClass.read_property('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('API_STATUS'):apiStatus,utilClass.read_property('USER_ID'):userId},
                ) 
            else:          
                stat= request.get (utilClass.read_property('STATUS'))
                if stat== utilClass.read_property ('OK'):
                    apiStatus=utilClass.read_property ('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    apiStatus = utilClass.read_property ('FAILURE')
                else:
                    apiStatus = utilClass.read_property ('SUCCESS')
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('API_RESPONSE'): request,utilClass.read_property('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('API_STATUS'):apiStatus,utilClass.read_property('USER_ID'):userId},
                    )
            logger.info(utilClass.read_property("EXITING_METHOD"))
        except Exception as exception:
            raise exception
    
    
    '''This method will store the response of tso for audit purpose'''
    def tso_response_audit(self,requestId,request,apiName,apiHomeDict,successDict,failureDict):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        tsoStatus=''
        dictionary={}
        try:
            dateNow = datetime.now ()
            #find json array
            logging = apiHomeDict.get(apiName)[0].logging
            if type(request) is list:
                for dict_var in request:
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        tsoStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        tsoStatus = utilClass.read_property('FAILURE')
                        break
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TSO_RESPONSE'): request,utilClass.read_property('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TSO_STATUS'):tsoStatus},
                )    
            else:
                stat = request.get(utilClass.read_property('STATUS'))
                if stat == utilClass.read_property ('OK'):
                    tsoStatus = utilClass.read_property('SUCCESS')
                    dictionary=successDict
                elif stat == utilClass.read_property ('NOT_OK'):
                    tsoStatus = utilClass.read_property('FAILURE')
                    dictionary=failureDict
                else:
                    tsoStatus=utilClass.read_property('SUCCESS')
                    dictionary=successDict
                logger.debug(apiName)
                logging = apiHomeDict.get(apiName)[0].logging
                if (logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TSO_RESPONSE'): request,utilClass.read_property('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TSO_STATUS'):tsoStatus},
                    )
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return dictionary
