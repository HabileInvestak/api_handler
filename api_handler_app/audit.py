from datetime import datetime
import logging

from api_handler_app.models import Audit
from api_handler_app.return_all_dict import ReturnAllDict
from utils import UtilClass


logger = logging.getLogger('api_handler_app.audit.py')

'''This class will store All the request and response to database for audit purpose.
we will store investak request,api request,tso response and api response and its status with timestamp'''
class AuditTrial():
    
    '''This method will store the request of Investak to database
    and it create request id which has unique id for the apiName when investak_api audit enable is Yes'''
    def investak_request_audit(self,userId,bodyContent,apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            logger.debug("Before Investak API audit enable")
            logger.debug("Logging="+logging)
            loggingSystem =systemDict.get(sourceUrl)[0].loggingRequired
            sourceRequestStatus = utilClass.read_property('SUCCESS')
            if(loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                logger.debug("Investak API audit enable")
                auditobj=Audit(user_id=userId, source_request=bodyContent,source_request_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress,request_id=requestId,source_request_status=sourceRequestStatus)
                auditobj.save()
                logger.debug("requestId="+str(requestId))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
    

    '''This method will store the request of api to database
    and it create request id which has unique id for the apiName when investak_api audit enable is Yes and api_tso audit enable yes'''
    def api_request_audit(self,requestId,request,apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging=apiHomeDict.get(apiName)[0].logging
            loggingSystem=systemDict.get(sourceUrl)[0].loggingRequired
            targetTransmitStatus = utilClass.read_property('SUCCESS')
            if(loggingSystem == utilClass.read_property ("YES") and logging==utilClass.read_property("YES") and utilClass.read_property('API_TSO_AUDIT_ENABLE')==utilClass.read_property("YES") and utilClass.read_property('INVESTAK_API_AUDIT_ENABLE')==utilClass.read_property("YES")):
                Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.read_property('TARGET_TRANSMIT'): request,utilClass.read_property('TARGET_TRANSMIT_TIME_STAMP'):dateNow,utilClass.read_property('USER_ID'):userId,utilClass.read_property('TARGET_TRANSMIT_STATUS'):targetTransmitStatus},
                )
            elif(loggingSystem == utilClass.read_property ("YES")):
                auditobj = Audit (user_id=userId, target_transmit=request, target_transmit_time_stamp=dateNow,api_name=apiName,ip_address=ipAddress,request_id=requestId,target_transmit_status=targetTransmitStatus)
                auditobj.save ()
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
    
    
    '''This method will store the response of api to database
    and check whether the response is list or dictionary and corresponding status is noted'''
    def api_response_audit(self,requestId,request,apiName,apiHomeDict,userId,systemDict,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        sourceTransmitStatus = ''
        try:
            dateNow = datetime.now ()
            logging = apiHomeDict.get(apiName)[0].logging
            loggingSystem=systemDict.get(sourceUrl)[0].loggingRequired 
            if type(request) is list:
                for dict_var in request:
                    print dict_var
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        sourceTransmitStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        sourceTransmitStatus = utilClass.read_property('FAILURE')
                        break
                if (loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('SOURCE_TRANSMIT'): request,utilClass.read_property('SOURCE_TRANSMIT_TIME_STAMP'):dateNow,utilClass.read_property('SOURCE_TRANSMIT_STATUS'):sourceTransmitStatus,utilClass.read_property('USER_ID'):userId},
                    ) 
            else:          
                stat= request.get (utilClass.read_property('STATUS'))
                if stat== utilClass.read_property ('OK'):
                    sourceTransmitStatus=utilClass.read_property ('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    sourceTransmitStatus = utilClass.read_property ('FAILURE')
                else:
                    sourceTransmitStatus = utilClass.read_property ('SUCCESS')
                if (loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('SOURCE_TRANSMIT'): request,utilClass.read_property('SOURCE_TRANSMIT_TIME_STAMP'):dateNow,utilClass.read_property('SOURCE_TRANSMIT_STATUS'):sourceTransmitStatus,utilClass.read_property('USER_ID'):userId},
                    )
            logger.info(utilClass.read_property("EXITING_METHOD"))
        except Exception as exception:
            raise exception
    
    
    '''This method will store the response of tso to store database
    and check whether the response is list or dictionary and corresponding status is noted'''
    def tso_response_audit(self,requestId,request,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        targetResponseStatus=''
        try:
            dateNow = datetime.now ()
            #find json array
            logging = apiHomeDict.get(apiName)[0].logging
            loggingSystem=systemDict.get(sourceUrl)[0].loggingRequired
            if type(request) is list:
                for dict_var in request:
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        targetResponseStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        targetResponseStatus = utilClass.read_property('FAILURE')
                        break
                if (loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TARGET_RESPONSE'): request,utilClass.read_property('TARGET_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TARGET_RESPONSE_STATUS'):targetResponseStatus},
                    )    
            else:
                stat = request.get(utilClass.read_property('STATUS'))
                if stat == utilClass.read_property ('OK'):
                    targetResponseStatus = utilClass.read_property('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    targetResponseStatus = utilClass.read_property('FAILURE')
                else:
                    targetResponseStatus=utilClass.read_property('SUCCESS')
                logger.debug(apiName)
                logging = apiHomeDict.get(apiName)[0].logging
                if (loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    Audit.objects.update_or_create (
                        request_id=requestId,
                        defaults={utilClass.read_property('TARGET_RESPONSE'): request,utilClass.read_property('TARGET_RESPONSE_TIME_STAMP'):dateNow,utilClass.read_property('TARGET_RESPONSE_STATUS'):targetResponseStatus},
                    )
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        
        
    '''This method will store the request and response of source,target to store database at single instances of thread process'''
    def all_request_response_audit(self,sourceUrl,userId,apiName,sourceRequestTimeStamp,requestValidateTimeStamp,
                                   targetTransmitTimeStamp,targetResponseTimeStamp,responseValidateTimeStamp,
                                   sourceTransmitTimeStamp,sourceRequest,targetTransmit,targetResponse,sourceTransmit,
                                   sourceRequestStatus,targetTransmitStatus,targetResponseStatus,sourceTransmitStatus,
                                   ipAddress):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        apiHomeDict = allList[0]
        systemDict = allList[7]
        try:
            logging = apiHomeDict.get(apiName)[0].logging
            logger.debug("ALL API audit")
            logger.debug("Logging="+logging)
            loggingSystem =systemDict.get(sourceUrl)[0].loggingRequired
            if(loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                logger.debug("Investak API audit enable")
                auditobj=Audit(user_id=userId,api_name=apiName,source_request_time_stamp=sourceRequestTimeStamp,request_validate_time_stamp=requestValidateTimeStamp,
                               target_transmit_time_stamp=targetTransmitTimeStamp,target_response_time_stamp=targetResponseTimeStamp,response_validate_time_stamp=responseValidateTimeStamp,
                               source_transmit_time_stamp=sourceTransmitTimeStamp,source_request=sourceRequest,target_transmit=targetTransmit,
                               target_response=targetResponse,source_transmit=sourceTransmit,source_request_status=sourceRequestStatus
                               ,target_transmit_status=targetTransmitStatus,target_response_status=targetResponseStatus,
                               source_transmit_status=sourceTransmitStatus,ip_address=ipAddress)
                auditobj.save()
                requestId=auditobj.request_id
                logger.debug("requestId="+str(requestId))
                print 'requestId',requestId
            elif(utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("NO") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("NO")):
                pass
            elif(loggingSystem == utilClass.read_property ("YES") and logging == utilClass.read_property ("YES")):
                if(utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("NO") and utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    auditobj=Audit(user_id=userId,api_name=apiName,request_validate_time_stamp=requestValidateTimeStamp,
                           target_transmit_time_stamp=targetTransmitTimeStamp,target_response_time_stamp=targetResponseTimeStamp,response_validate_time_stamp=responseValidateTimeStamp,
                           target_transmit=targetTransmit,target_response=targetResponse,
                           target_transmit_status=targetTransmitStatus,
                           target_response_status=targetResponseStatus,
                           ip_address=ipAddress)
                    auditobj.save()
                    requestId=auditobj.request_id
                    logger.debug("requestId="+str(requestId))
                    print 'requestId',requestId
                
                elif(utilClass.read_property ('API_TSO_AUDIT_ENABLE') == utilClass.read_property ("NO") and utilClass.read_property ('INVESTAK_API_AUDIT_ENABLE') == utilClass.read_property ("YES")):
                    auditobj=Audit(user_id=userId,api_name=apiName,source_request_time_stamp=sourceRequestTimeStamp,request_validate_time_stamp=requestValidateTimeStamp,
                           response_validate_time_stamp=responseValidateTimeStamp,
                           source_transmit_time_stamp=sourceTransmitTimeStamp,source_request=sourceRequest,
                           source_transmit=sourceTransmit,source_request_status=sourceRequestStatus
                           ,source_transmit_status=sourceTransmitStatus,ip_address=ipAddress)
                auditobj.save()
                requestId=auditobj.request_id
                logger.debug("requestId="+str(requestId))
                print 'requestId',requestId
                
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
