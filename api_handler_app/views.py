import json
import logging


from threading import Thread
from datetime import datetime
from django.db.models import Q
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from api_handler_app.models import Audit
from api_handler_app.return_all_dict import ReturnAllDict
from api_handler_app.serializers import AuditSerializer
from audit import AuditTrial
from request import RequestClass
from utils import UtilClass
from validate import Validate


logger = logging.getLogger('api_handler_app.views.py')


'''Provides you with initial token for Login,it will call two api name for create initial token and it will check input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and 
check input encryption,response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_initial_token(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"): 
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName = utilClass.read_property ("GET_INITIAL_KEY")
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)
            url=targetUrlDomain+''+urlPath
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
            '''Store InvestAK request for audit trial purpose'''
            validate.record_and_field_separator(systemDict,sourceUrl)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            sourceRequest=jsonObject
            resultAll = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
            result=resultAll[0]
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=resultAll
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(resultAll,status=status.HTTP_200_OK)
            tomcatCount=""
            jKey=""
            jData=""
            output = requestObj.send_request(bodyContent, url, authorization, "", tomcatCount, jKey, jData)
            initialPublicKey1 = output[utilClass.read_property('PUBLIC_KEY')]
            tomcatCount = output[utilClass.read_property('TOMCAT_COUNT')]
            publicKey1Pem = requestObj.b64_decode(initialPublicKey1)
            keyPair = requestObj.generate_key_pair()
            publicKey2Pem = requestObj.get_public_key_pem(keyPair)
            privateKey2Pem = requestObj.get_private_key_pem(keyPair)
            publicKey1 = requestObj.import_key(publicKey1Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("NO"):
                    jData = requestObj.encrypt(publicKey2Pem, publicKey1, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_INPUT_ENCRYPTION_WITH_NO"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA")) 
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))    
            requestValidateTimeStamp=datetime.now ()
            jKey = requestObj.get_jkey(publicKey1Pem)
            url = apiHomeDict.get(utilClass.read_property('GET_PRE_AUTHENTICATION_KEY'))[0].url
            bodyContent= utilClass.read_property('YES')
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print output
            print "After send request"
            targetResponseTimeStamp=datetime.now ()
            targetResponse=output
            targetResponseStatus=validate.get_target_response_status(output)
            stat = output.get (utilClass.read_property ('STATUS'))
            emsg = output.get (utilClass.read_property ('ERROR'))
            if utilClass.read_property("STATUS") in output and output[utilClass.read_property("STATUS")]==utilClass.read_property("OK"):
                initialPublicKey3 = output[utilClass.read_property('PUBLIC_KEY3')]
                privateKey2 = requestObj.import_key(privateKey2Pem)
                print "Before algo"
                encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
                if(utilClass.read_property('RSA')==encryptionMethod):
                    decryptedPublicKey3 = requestObj.decrypt(initialPublicKey3, privateKey2)
                else:
                    raise Exception(utilClass.read_property("ALGORITHM"))
                initialToken = utilClass.replace_text(requestObj.b64_encode(privateKey2Pem),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(decryptedPublicKey3),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(tomcatCount),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(userId),"\n","")
            if stat==utilClass.read_property('OK'):
                output = {utilClass.read_property('STATUS'):stat,utilClass.read_property('INITIAL_TOKEN'): initialToken,utilClass.read_property('TOMCAT_COUNT'):tomcatCount}
            else:
                output = {utilClass.read_property ('STATUS'): stat,utilClass.read_property ('ERROR'): emsg}
            print "#####################" 
            print output
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            print "output",output
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=output
            sourceTransmitStatus=validate.get_source_transmit_status(output[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK) 
    
  
    
'''Get login mode and it will check input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and 
check input encryption,response decryption ,rsa algorithm'''
@api_view(["POST"])    
def get_login_mode(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"):
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict)
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName = utilClass.read_property ("LOGIN_MODE")
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)
            url=targetUrlDomain+''+urlPath
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
            '''Store InvestAK request for audit trial purpose'''
            validate.record_and_field_separator(systemDict,sourceUrl)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            if bodyContent:
                jsonObject = json.loads (bodyContent)
                userId=jsonObject.get('uid')
                sourceRequest=jsonObject
                resultAll = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
                result=resultAll[0]
                requestValidateTimeStamp=datetime.now ()
                if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                    sourceTransmitTimeStamp=datetime.now ()
                    sourceTransmit=resultAll
                    sourceTransmitStatus=validate.get_source_transmit_status(result)
                    auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                      targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                      sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                      sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                      sourceTransmitStatus, ipAddress))
                    auditThread.daemon = True
                    auditThread.start()
                    logger.info(utilClass.read_property("EXITING_METHOD"))
                    return Response(resultAll,status=status.HTTP_200_OK)
            tomcatCount=""
            jKey=""
            jData=""
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("NO"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_INPUT_ENCRYPTION_WITH_NO"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            requestValidateTimeStamp=datetime.now ()
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, "", tomcatCount, jKey, jData)
            print "output final",output
            output = json.loads(output)
            targetResponseTimeStamp=datetime.now ()
            targetResponse=output
            targetResponseStatus=validate.get_target_response_status(output)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=output
            sourceTransmitStatus=validate.get_source_transmit_status(output[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK)        


'''First step in login and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_login_2fa(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict)
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName = utilClass.read_property ("LOGIN_2FA")
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            bodyContent = request.body
            logger.debug("userJSON="+bodyContent)
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    publicKey3Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN")) 
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            contentType=request.content_type
            validate.content_type(contentType)
            logger.debug("userId="+userId)
            jKey = requestObj.get_jkey(publicKey3Pem)
            validate.record_and_field_separator(systemDict,sourceUrl)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            logger.debug("result="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            sourceRequest=jsonObject
            logger.debug("before validation_and_manipulation")
            resultAll = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            result=resultAll[0]
            requestValidateTimeStamp=datetime.now ()
            logger.debug("After validation_and_manipulation="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                logger.debug("Inside Status")
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=resultAll
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (resultAll,status=status.HTTP_200_OK)
            publicKey3=requestObj.import_key(publicKey3Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_3"):
                    jData = requestObj.encrypt(json.dumps(result),publicKey3, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_3"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))  
            requestValidateTimeStamp=datetime.now ()  
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            targetResponseTimeStamp=datetime.now ()
            targetResponse=output
            targetResponseStatus=validate.get_target_response_status(output)
            logger.debug(dictionary)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=output
            sourceTransmitStatus=validate.get_source_transmit_status(output[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)           
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK)
    

    
'''Authenticates the user with password and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_valid_pwd(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict)
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName = utilClass.read_property("VALID_PASSWORD")
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            bodyContent = request.body
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    publicKey3Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            contentType=request.content_type
            validate.content_type(contentType)
            jKey = requestObj.get_jkey(publicKey3Pem)
            validate.record_and_field_separator(systemDict,sourceUrl)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            sourceRequest=jsonObject
            resultAll = validate.validation_and_manipulation (jsonObject,apiName,inputDict)
            result=resultAll[0]
            requestValidateTimeStamp=datetime.now ()
            logger.debug(result)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=resultAll
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(resultAll,status=status.HTTP_200_OK)
    
            result = utilClass.password_hash(result)
            jsonData = json.dumps (result)
            publicKey3=requestObj.import_key(publicKey3Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_3"):
                    jData = requestObj.encrypt(jsonData,publicKey3, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_3"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            requestValidateTimeStamp=datetime.now ()
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            targetResponseTimeStamp=datetime.now ()
            targetResponse=output
            targetResponseStatus=validate.get_target_response_status(output)
            logger.debug("Before success validation")
            output = validate.validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call auditTrial.api_response_audit
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=output
            sourceTransmitStatus=validate.get_source_transmit_status(output[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        logger.debug(err)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK)    


'''Authenticates the answers in 2FA Q&A mode and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_valid_ans(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property('METHOD_TYPE'):
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict)
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName = utilClass.read_property ("VALID_ANSWER")
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            bodyContent = request.body
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    privateKey2Pem=requestObj.b64_decode(authorization[0].replace("\n",""))
                    publicKey3Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            contentType=request.content_type
            validate.content_type(contentType)
            jKey = requestObj.get_jkey(publicKey3Pem)
            validate.record_and_field_separator(systemDict,sourceUrl)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            sourceRequest=jsonObject
            resultAll = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            result=resultAll[0]
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=resultAll
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (resultAll,status=status.HTTP_200_OK)
            jsonData = json.dumps(result)
            publicKey3=requestObj.import_key(publicKey3Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_3"):
                    jData = requestObj.encrypt(jsonData,publicKey3, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_3"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            requestValidateTimeStamp=datetime.now ()
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            validate.get_session_expired_response(output)
            encryptedData=output[utilClass.read_property("JENCRESP")]
            privateKey2 = requestObj.import_key(privateKey2Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_2"):
                    decryptedData=requestObj.decrypt(encryptedData,privateKey2)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_2"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            logger.debug(decryptedData)
            decryptedJson = json.loads(decryptedData)
            print decryptedJson
            logger.debug(decryptedJson)
            targetResponseTimeStamp=datetime.now ()
            targetResponse=decryptedJson
            targetResponseStatus=validate.get_target_response_status(decryptedJson)
            stat = decryptedJson.get (utilClass.read_property ('STATUS'))
            if decryptedJson[utilClass.read_property('STATUS')]==utilClass.read_property('OK'):
                accessToken = utilClass.replace_text(requestObj.b64_encode(privateKey2Pem), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(decryptedJson["sUserToken"]), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(tomcatCount), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(userId), "\n", "")
                decryptedJson[utilClass.read_property('ACCESS_TOKEN')] = accessToken               
            else:
                emsg = decryptedJson[utilClass.read_property ('ERROR_MSG')]
                decryptedJson = {utilClass.read_property('STATUS'): stat,utilClass.read_property('ERROR_MSG'): emsg}
            logger.debug(str(decryptedJson))
            decryptedJson = validate.validation_and_manipulation (decryptedJson, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=decryptedJson
            sourceTransmitStatus=validate.get_source_transmit_status(decryptedJson[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(decryptedJson,status=status.HTTP_200_OK)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK)


'''This method allows you to all api name request from the application and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_api_handler_request(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    apiName=''
    userId=''
    sourceUrl=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    sourceRequestTimeStamp=None
    requestValidateTimeStamp=None
    targetTransmitTimeStamp=None
    targetResponseTimeStamp=None
    responseValidateTimeStamp=None
    sourceTransmitTimeStamp=None
    sourceRequest=''
    targetTransmit='' 
    targetResponse=''
    sourceTransmit='' 
    sourceRequestStatus='' 
    targetTransmitStatus='' 
    targetResponseStatus=''
    sourceTransmitStatus=''
    ipAddress=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            sourceRequestTimeStamp=datetime.now ()
            sourceRequest=request.body
            sourceRequestStatus=utilClass.read_property ('SUCCESS')
            path_var=request.path
            path_var=path_var.replace("/","")
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            sourceUrl=validate.get_source_url(requestUrl,systemDict)
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            apiName=utilClass.read_property(path_var)
            urlPath =validate.get_target_url_path(apiHomeDict,apiName)    
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            ipAddress=utilClass.get_client_ip(request)
            bodyContent = request.body
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization = authorization.split("-")
                    publicKey4Pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
                    tomcatCount = requestObj.b64_decode(authorization[2].replace("\n", ""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            contentType=request.content_type
            validate.content_type(contentType)
            jKey = requestObj.get_jkey(publicKey4Pem)
            validate.record_and_field_separator(systemDict,sourceUrl)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=result
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            sourceRequest=jsonObject
            resultAll = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            result=resultAll[0]
            requestValidateTimeStamp=datetime.now ()
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                sourceTransmitTimeStamp=datetime.now ()
                sourceTransmit=resultAll
                sourceTransmitStatus=validate.get_source_transmit_status(result)
                auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
                auditThread.daemon = True
                auditThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (resultAll,status=status.HTTP_200_OK)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            encryptionMethod=systemDict.get(sourceUrl)[0].encryptionMethod
            if(utilClass.read_property('RSA')==encryptionMethod):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_4"):
                    jData = requestObj.encrypt(jsonData, publicKey4, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_4"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            requestValidateTimeStamp=datetime.now ()
            tomcatCount = requestObj.get_tomcat_count(tomcatCount)
            targetTransmitTimeStamp=datetime.now ()
            targetTransmit=result
            targetTransmitStatus=utilClass.read_property ('SUCCESS')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print 'output ',output
            targetResponseTimeStamp=datetime.now ()
            output=validate.invalid_data_account_info(output,apiName)
            targetResponse=output
            targetResponseStatus=validate.get_target_response_status(output)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            print 'output',output
            responseValidateTimeStamp=datetime.now ()
            sourceTransmit=output
            sourceTransmitStatus=validate.get_source_transmit_status(output[0])
            sourceTransmitTimeStamp=datetime.now ()
            auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
            auditThread.daemon = True
            auditThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        sourceTransmitTimeStamp=datetime.now ()
        sourceTransmit=output
        sourceTransmitStatus=validate.get_source_transmit_status(output)
        auditThread = Thread(target =auditTrial.all_request_response_audit,args=(sourceUrl, userId, apiName, sourceRequestTimeStamp, requestValidateTimeStamp, 
                                                  targetTransmitTimeStamp, targetResponseTimeStamp, responseValidateTimeStamp, 
                                                  sourceTransmitTimeStamp, sourceRequest, targetTransmit, targetResponse, 
                                                  sourceTransmit, sourceRequestStatus, targetTransmitStatus, targetResponseStatus, 
                                                  sourceTransmitStatus, ipAddress))
        auditThread.daemon = True
        auditThread.start()
        return Response(output,status=status.HTTP_200_OK)
 
 
''' This method is used to read update excel and property file without restarting server''' 
@api_view(["POST"])
def get_excel_property_update(request):
    utilClass=UtilClass()
    validate=Validate()
    output={}
    try:
        #ReturnAllDict().update_excel_property()
        #return JsonResponse("ok",status=status.HTTP_200_OK, safe=False)
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ReturnAllDict().update_excel_property()
            msg=utilClass.read_property("UPDATE_EXCEL_PROPERTY")
            output[utilClass.read_property ('MESSAGE')]=msg
            output[utilClass.read_property ('STATUS')]=utilClass.read_property ('OK')
            return JsonResponse(output,status=status.HTTP_200_OK)
    except Exception as exception:
        msg=utilClass.read_property("UPDATE_EXCEL_PROPERTY_FAIL")
        msg=str(exception)
        output=validate.create_error_response(msg)
        return Response(output,status=status.HTTP_200_OK)  
   
''' This method is used to retrieve all pending api that is still in processing that is any one of api status or tso status not updated'''     
@api_view(["POST"])
def get_retrieve_all_pending_api(request):
    utilClass=UtilClass()
    validate=Validate()
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            audit = Audit.objects.filter(
                Q(target_transmit_status="S"),#Q(source_request_status="S") & 
                Q(source_transmit_status="") | Q(target_response_status="")
                )
            serializer = AuditSerializer(audit, many=True)
            return Response(serializer.data) 
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        return Response(output,status=status.HTTP_200_OK)
        #except Audit.DoesNotExist:

''' This method is used to retrieve all success or failure api
In case success response we want api status and tso status is success only,
In case failure response we want any one of api status or tso status is failure only'''
@api_view(["POST"])
def get_retrieve_all_success_or_failure_api(request):
    utilClass=UtilClass()
    validate=Validate()
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            bodyContent = request.body
            jsonObject = json.loads (bodyContent)
            status=str(jsonObject.get("status"))
            if status==utilClass.read_property ('SUCCESS'):
                audit = Audit.objects.filter(source_request_status=status,target_transmit_status=status,target_response_status=status,source_transmit_status=status,)
            if status==utilClass.read_property ('FAILURE'):
                audit = Audit.objects.filter(Q(source_transmit_status=status) | Q(target_response_status=status))
            serializer = AuditSerializer(audit, many=True)
            return Response(serializer.data) 
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        return Response(output,status=status.HTTP_200_OK)
        #except Audit.DoesNotExist:
    
    
''' This method is used to create invalid url response when page is not found error is occur'''
def page_not_found(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    utilClass=UtilClass()
    try:
        validate=Validate()
        output=validate.create_error_response(utilClass.read_property("INVALID_URL"))
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return JsonResponse(output,safe=False)
    except Exception as exception:
        logger.exception(exception)
        raise Exception(exception)      
    
     
''' This method is used to create server error response when server error is occur'''
def server_error(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    utilClass=UtilClass()
    try:
        print 'request',request
        validate=Validate()
        output=validate.create_error_response(utilClass.read_property("SERVER_ERROR"))
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return JsonResponse(output,safe=False)
    except Exception as exception:
        logger.exception(exception)
        raise Exception(exception)      