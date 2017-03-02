import json
import logging


from threading import Thread

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
    requestId=''
    apiName=''
    userId=""
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"): 
            #print sourceUrl
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property("GET_INITIAL_KEY"))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))
            url=targetUrlDomain+''+urlPath
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            apiName = utilClass.read_property ("GET_INITIAL_KEY")
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
            '''Store InvestAK request for audit trial purpose'''
            requestId = utilClass.generate_request_id("ANAN",apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            result = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(result,status=status.HTTP_200_OK)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            jKey = requestObj.get_jkey(publicKey1Pem)
            url = apiHomeDict.get(utilClass.read_property('GET_PRE_AUTHENTICATION_KEY'))[0].url
            bodyContent= utilClass.read_property('YES')
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print output
            print "After send request"
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
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, output,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
            if stat==utilClass.read_property('OK'):
                output = {utilClass.read_property('STATUS'):stat,utilClass.read_property('INITIAL_TOKEN'): initialToken,utilClass.read_property('TOMCAT_COUNT'):tomcatCount}
            else:
                output = {utilClass.read_property ('STATUS'): stat,utilClass.read_property ('ERROR'): emsg}
            print "#####################" 
            print output
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            print "output",output
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        print auditTrial
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
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
    requestId=''
    apiName=''
    userId=""
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"):
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property("LOGIN_MODE"))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))
            url=targetUrlDomain+''+urlPath
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            apiName = utilClass.read_property ("LOGIN_MODE")
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
           
            '''Store InvestAK request for audit trial purpose'''
            requestId = utilClass.generate_request_id("ANAN",apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            if bodyContent:
                jsonObject = json.loads (bodyContent)
                userId=jsonObject.get('uid')
                result = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
                if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                    apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                    apiResThread.daemon = True
                    apiResThread.start()
                    logger.info(utilClass.read_property("EXITING_METHOD"))
                    return Response(result,status=status.HTTP_200_OK)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            output = requestObj.send_request(bodyContent, url, authorization, "", tomcatCount, jKey, jData)
            print "output final",output
            output = json.loads(output)
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, output,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        print auditTrial
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
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
    requestId=''
    apiName=''
    userId=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property("LOGIN_2FA"))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            apiName = utilClass.read_property ("LOGIN_2FA")
            bodyContent = request.body
            logger.debug("userJSON="+bodyContent)
            logger.debug("requestId before input availability and format="+str(requestId))
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
            if contentType:
                if contentType==utilClass.read_property("CONTENT_TYPE"):
                    pass
                else:
                    raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            else:
                raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE")) 
            requestId = utilClass.generate_request_id(userId,apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            logger.debug("userId="+userId)
            jKey = requestObj.get_jkey(publicKey3Pem)
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            logger.debug("result="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            logger.debug("before validation_and_manipulation")
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            logger.debug("After validation_and_manipulation="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                logger.debug("Inside Status")
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, output,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
            logger.debug(dictionary)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)           
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
        return Response(output)
    

    
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
    requestId=''
    apiName=''
    userId=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property("VALID_PASSWORD"))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            apiName = utilClass.read_property("VALID_PASSWORD")
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
            if contentType:
                if contentType==utilClass.read_property("CONTENT_TYPE"):
                    pass
                else:
                    raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            else:
                raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            requestId = utilClass.generate_request_id(userId,apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            jKey = requestObj.get_jkey(publicKey3Pem)
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject,apiName,inputDict)
            logger.debug(result)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(result,status=status.HTTP_200_OK)
    
            result = utilClass.password_hash(result)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)

            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, output,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
            logger.debug("Before success validation")
            output = validate.validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call auditTrial.api_response_audit
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        logger.debug(err)
        output=validate.create_error_response(err)
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
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
    requestId=''
    apiName=''
    userId=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property('METHOD_TYPE'):
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property("VALID_ANSWER"))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            apiName = utilClass.read_property ("VALID_ANSWER")
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
            if contentType:
                if contentType==utilClass.read_property("CONTENT_TYPE"):
                    pass
                else:
                    raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            else:
                raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            requestId = utilClass.generate_request_id(userId,apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            jKey = requestObj.get_jkey(publicKey3Pem)
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            stat = output.get (utilClass.read_property ('STATUS'))
            
            encryptedData=output["jEncResp"]
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
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, decryptedJson,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
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
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, decryptedJson, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(decryptedJson,status=status.HTTP_200_OK)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
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
    requestId=''
    apiName=''
    userId=''
    dictionary={}
    returnAllDict = ReturnAllDict()
    allList = returnAllDict.return_dict()
    apiHomeDict = allList[0]
    inputDict = allList[1]
    successDict = allList[2]
    failureDict = allList[3]
    systemDict=allList[7]
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            path_var=request.path
            path_var=path_var.replace("/","")
            httpScheme= request.scheme               # http or https
            domainName= request.META['HTTP_HOST']
            requestUrl=httpScheme+'://'+domainName+'/'
            try:
                sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_SOURCE_URL")) 
            targetUrlDomain=systemDict.get(sourceUrl)[0].targetUrl
            try:
                urlPath = apiHomeDict.get(utilClass.read_property(path_var))[0].url
            except Exception:
                raise ValueError(utilClass.read_property("INVALID_URL"))            
            url=targetUrlDomain+''+urlPath
            ipAddress=utilClass.get_client_ip(request)
            ipAddress=utilClass.get_client_ip(request)
            apiName=utilClass.read_property(path_var)
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
            if contentType:
                if contentType==utilClass.read_property("CONTENT_TYPE"):
                    pass
                else:
                    raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            else:
                raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            requestId=utilClass.generate_request_id(userId,apiName)
            investakReqThread = Thread(target = auditTrial.investak_request_audit , args=(userId, bodyContent, apiName,apiHomeDict,ipAddress,requestId,systemDict,sourceUrl))
            investakReqThread.daemon = True
            investakReqThread.start()
            jKey = requestObj.get_jkey(publicKey4Pem)
            recordSeperator=systemDict.get(sourceUrl)[0].recordSeperator
            if recordSeperator and recordSeperator==utilClass.read_property("CR/LF"):
                pass
            else:
                pass
            fieldSeperator=systemDict.get(sourceUrl)[0].fieldSeperator
            if fieldSeperator:
                pass
            else:
                pass
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict,sourceUrl)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, result, apiName,apiHomeDict,userId,systemDict,sourceUrl))
                apiResThread.daemon = True
                apiResThread.start()
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result,status=status.HTTP_200_OK)
            apiReqThread = Thread(target = auditTrial.api_request_audit , args=(requestId, result, apiName,userId,apiHomeDict,ipAddress,systemDict,sourceUrl))
            apiReqThread.daemon = True
            apiReqThread.start()
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
            tomcatCount = requestObj.get_tomcat_count(tomcatCount)
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print 'output ',output
            tsoResThread = Thread(target = auditTrial.tso_response_audit , args=(requestId, output,apiName,apiHomeDict,successDict,failureDict,systemDict,sourceUrl))
            tsoResThread.daemon = True
            tsoResThread.start()
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
            apiResThread.daemon = True
            apiResThread.start()
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output,status=status.HTTP_200_OK)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        apiResThread = Thread(target = auditTrial.api_response_audit , args=(requestId, output, apiName,apiHomeDict,userId,systemDict,sourceUrl))
        apiResThread.daemon = True
        apiResThread.start()
        return Response(output,status=status.HTTP_200_OK)
 
 
''' This method is used to read update excel and property file without restarting server''' 
@api_view(["POST"])
def get_excel_property_update(request):
    utilClass=UtilClass()
    validate=Validate()
    output={}
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ReturnAllDict().update_excel_property()
            msg=utilClass.read_property("UPDATE_EXCEL_PROPERTY")
            output[utilClass.read_property ('MESSAGE')]=msg
            output[utilClass.read_property ('STATUS')]=utilClass.read_property ('OK')
            return JsonResponse(output,status=status.HTTP_200_OK) 
    except Exception:
        msg=utilClass.read_property("UPDATE_EXCEL_PROPERTY_FAIL")
        output=validate.create_error_response(msg)
        return Response(output,status=status.HTTP_200_OK)  
   
''' This method is used to retrieve all pending api that is still in processing that is any one of api status or tso status not updated'''     
@api_view(["POST"])
def get_retrieve_all_pending_api(request):
    utilClass=UtilClass()
    validate=Validate()
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            audit = Audit.objects.filter(Q(api_status="") | Q(tso_status=""))
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
                audit = Audit.objects.filter(api_status=status,tso_status=status)
            if status==utilClass.read_property ('FAILURE'):
                audit = Audit.objects.filter(Q(api_status=status) | Q(tso_status=status))
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
        return JsonResponse(output)
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
        return JsonResponse(output)
    except Exception as exception:
        logger.exception(exception)
        raise Exception(exception)      