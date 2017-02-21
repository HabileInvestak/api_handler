import json
import logging

from django.http import JsonResponse
from properties.p import Property
from rest_framework.decorators import api_view
from rest_framework.response import Response

from api_handler.wsgi import ReturnAllDict
from audit import AuditTrial
from request import RequestClass
from utils import UtilClass
from validate import Validate


returnAllDict = ReturnAllDict()
allList = returnAllDict.return_dict()
apiHomeDict = allList[0]
inputDict = allList[1]
successDict = allList[2]
failureDict = allList[3]
jsonDict = allList[4]
listDict = allList[5]

logger = logging.getLogger('api_handler_app.views.py')

prop = Property ()
#propObj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
#propObj = prop.load_property_files ('E:\\Investak\\investak.properties')  # ranjith


'''Provides you with initial token for Login,it will call two api name for create initial token and it will check input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and 
check input encryption,response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_initial_token(request):
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"):
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("GET_INITIAL_KEY"))[0].url
            apiName = utilClass.read_property ("GET_INITIAL_KEY")
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
            userId=""
            '''Store InvestAK request for audit trial purpose'''
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            
            result = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit(requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(result)
            requestId= auditTrial.api_request_audit(requestId, result, apiName,userId,apiHomeDict,ipAddress)
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
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
                if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
                    decryptedPublicKey3 = requestObj.decrypt(initialPublicKey3, privateKey2)
                else:
                    raise Exception(utilClass.read_property("ALGORITHM"))
                initialToken = utilClass.replace_text(requestObj.b64_encode(privateKey2Pem),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(decryptedPublicKey3),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(tomcatCount),"\n","") + utilClass.read_property('HYPEN') + utilClass.replace_text(requestObj.b64_encode(userId),"\n","")
            dictionary =auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            if stat==utilClass.read_property('OK'):
                output = {utilClass.read_property('STATUS'):stat,utilClass.read_property('INITIAL_TOKEN'): initialToken,utilClass.read_property('TOMCAT_COUNT'):tomcatCount}
            else:
                output = {utilClass.read_property ('STATUS'): stat,utilClass.read_property ('ERROR'): emsg}
            print "#####################" 
            print output
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            print "output",output
            print "##"
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        print auditTrial
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)
    
    
'''Get login mode and it will check input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and 
check input encryption,response decryption ,rsa algorithm'''
@api_view(["POST"])    
def get_login_mode(request):
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    try:
        if request.method == utilClass.read_property("METHOD_TYPE"):
            bodyContent = request.body
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("LOGIN_MODE"))[0].url
            apiName = utilClass.read_property ("LOGIN_MODE")
            authorization = request.META.get(utilClass.read_property("AUTHORIZATION"))
            userId=""
            '''Store InvestAK request for audit trial purpose'''
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            if bodyContent:
                jsonObject = json.loads (bodyContent)
                userId=jsonObject.get('uid')
                result = validate.validation_and_manipulation (jsonObject, apiName,inputDict)
                if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                    auditTrial.api_response_audit(requestId, result,apiName,apiHomeDict,userId)
                    logger.info(utilClass.read_property("EXITING_METHOD"))
                    return Response(result)
            requestId= auditTrial.api_request_audit(requestId, result, apiName,userId,apiHomeDict,ipAddress)
            tomcatCount=""
            jKey=""
            jData=""
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary =auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)            
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        print auditTrial
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)        


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
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("LOGIN_2FA"))[0].url
            apiName = utilClass.read_property ("LOGIN_2FA")
            bodyContent = request.body
            logger.debug("userJSON="+bodyContent)
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            logger.debug("userId="+userId)
            jKey = requestObj.get_jkey(publicKey3Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            logger.debug("result="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial. api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            logger.debug("before validation_and_manipulation")
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            logger.debug("After validation_and_manipulation="+str(result))
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                logger.debug("Inside Status")
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            publicKey3=requestObj.import_key(publicKey3Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            logger.debug(dictionary)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)           
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Provide you with pre-authentication key for encryption and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_login(request):

    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = utilClass.read_property ("GET_PRE_AUTHENTICATION_KEY")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization = authorization.split("-")
                    publicKey3Pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
                    tomcatCount = requestObj.b64_decode(authorization[2].replace("\n", ""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            jKey = requestObj.requestObj.get_jkey(publicKey3Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)

            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey3 = requestObj.import_key(publicKey3Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            tomcatCount = requestObj.get_tomcat_count(tomcatCount)
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)

   
'''Gives you information about client enabled data and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_default_login(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("DEFAULT_LOGIN"))[0].url
            apiName = utilClass.read_property ("DEFAULT_LOGIN")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    publicKey4Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            logger.debug("default login validation_and_manipulation result=")
            logger.debug(result)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4=requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_4"):
                    jData = requestObj.encrypt(jsonData,publicKey4, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_4"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            
            logger.debug("Before result")
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            logger.debug(output)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
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
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("VALID_PASSWORD"))[0].url
            apiName = utilClass.read_property("VALID_PASSWORD")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey3Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject,apiName,inputDict)
            logger.debug(result)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit(requestId,result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response(result)
    
            result = utilClass.password_hash(result)
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps (result)
            publicKey3=requestObj.import_key(publicKey3Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary=auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            logger.debug("Before success validation")
            output = validate.validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        logger.debug(err)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)    


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
    try:
        if request.method == utilClass.read_property('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("VALID_ANSWER"))[0].url
            apiName = utilClass.read_property ("VALID_ANSWER")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey3Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey3=requestObj.import_key(publicKey3Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_2"):
                    decryptedData=requestObj.decrypt(encryptedData,privateKey2)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_2"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            logger.debug(decryptedData)
            decryptedJson = json.loads(decryptedData)
            logger.debug(decryptedJson)
            dictionary =auditTrial.tso_response_audit (requestId, decryptedJson,apiName,apiHomeDict,successDict,failureDict)
            logger.debug(dictionary)
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
            auditTrial. api_response_audit (requestId, decryptedJson,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(decryptedJson)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Provides you with account details and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_account_info(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("ACCOUNT_INFO"))[0].url
            apiName = utilClass.read_property ("ACCOUNT_INFO")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    publicKey4Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4=requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_4"):
                    jData = requestObj.encrypt(jsonData,publicKey4, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_4"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''This method used to check log in bypass'''
@api_view(["POST"])
def get_login_by_pass(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    logger.info(utilClass.read_property("EXITING_METHOD"))
    return ''

'''Gives retention types for the particular exchange and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_load_retention_type(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("LOAD_RETENSION_TYPE"))[0].url
            apiName = utilClass.read_property ("LOAD_RETENSION_TYPE")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            authorization = request.META.get(utilClass.read_property('AUTHORIZATION'))
            if authorization:
                try:
                    authorization=authorization.split("-")
                    publicKey4Pem = requestObj.b64_decode(authorization[1].replace("\n",""))
                    tomcatCount= requestObj.b64_decode(authorization[2].replace("\n",""))
                    userId= requestObj.b64_decode(authorization[3].replace("\n",""))
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            else:
                raise ValueError(utilClass.read_property("INVALID_TOKEN"))
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4=requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
                if apiHomeDict.get(apiName)[0].inputEncryption==utilClass.read_property("YES_WITH_PUBLIC_KEY_4"):
                    jData = requestObj.encrypt(jsonData,publicKey4, 2048)
                else:
                    raise Exception(utilClass.read_property("INVALID_YES_WITH_PUBLIC_KEY_4"))
                if apiHomeDict.get(apiName)[0].resonseDecryption==utilClass.read_property("NA"):
                    pass
                else:
                    raise Exception(utilClass.read_property("INVALID_RESPONSE_DECRYPTION_WITH_NA"))
            else:
                raise Exception(utilClass.read_property("ALGORITHM"))
            tomcatCount=requestObj.get_tomcat_count(tomcatCount)
            
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print "output",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            print "dictionary",dictionary
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            print "output",output
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Check circuit limt for the order price and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_check_crkt_price_range(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:  
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("CHECK_CORRECT_PRICE_RANGE"))[0].url
            apiName = utilClass.read_property ("CHECK_CORRECT_PRICE_RANGE")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''GTD validations are done if retention is selected and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_validate_GTD(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("VALIDATE_GTD"))[0].url
            apiName = utilClass.read_property ("VALIDATE_GTD")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            print "Before send request"
            output = requestObj.send_request(bodyContent, url, authorization, userId, tomcatCount, jKey, jData)
            print "After send request",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)    

'''Validates Stop loss price and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_validate_SLM_price(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("VALIDATE_SLM_PRICE"))[0].url
            apiName = utilClass.read_property ("VALIDATE_SLM_PRICE")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Allows you to place order for selected scrip and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_place_order(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("PLACE_ORDER"))[0].url
            apiName = utilClass.read_property ("PLACE_ORDER")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            print bodyContent
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            print "after result",result 
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)

'''Allows you to view the placed orders and their status and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_order_book(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("ORDER_BOOK"))[0].url
            apiName = utilClass.read_property ("ORDER_BOOK")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            print output
            logger.debug(output)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Allows you to modify open orders and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_modify_order(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("MODIFY_ORDER"))[0].url
            apiName = utilClass.read_property ("MODIFY_ORDER")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)    
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output) 

'''Allows you to cancel an open order and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_cancel_order(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("CANCEL_ORDER"))[0].url
            apiName = utilClass.read_property ("CANCEL_ORDER")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)

'''Allows you to view the order history for the Order and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_order_history(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("ORDER_HISTORY"))[0].url
            apiName = utilClass.read_property ("ORDER_HISTORY")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)

'''Allows you to view trade details and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_trade_book(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("TRADE_BOOK"))[0].url
            apiName = utilClass.read_property ("TRADE_BOOK")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            print output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Allows you to view position book details and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''   
@api_view(["POST"])
def get_position_book(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("POSITION_BOOK"))[0].url
            apiName = utilClass.read_property ("POSITION_BOOK")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''This Allows user to view the holdings and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_holding(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("HOLDING"))[0].url
            apiName = utilClass.read_property ("HOLDING")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Allows you to view segment wise RMS limits and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_limits(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("LIMITS"))[0].url
            apiName = utilClass.read_property ("LIMITS")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            print "output=",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Allows you to view segment wise RMS limits and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_check_transaction_password(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("CHECK_TRANSACTION_PASSWORD"))[0].url
            logger.debug("url",url)
            apiName = utilClass.read_property ("CHECK_TRANSACTION_PASSWORD")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            print "output=",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''Provides you w ith user details and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_user_profile(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("USER_PROFILE"))[0].url
            apiName = utilClass.read_property ("USER_PROFILE")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            print "jsonObject-------------------",jsonObject
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)




'''Loads open order to set alerts based on trade and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_open_orders(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("OPEN_ORDERS"))[0].url
            apiName = utilClass.read_property ("OPEN_ORDERS")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)
    
'''List of End of the Day holdings for clients and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_bo_holdings(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method ==utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("BO_HOLDINGS"))[0].url
            apiName = utilClass.read_property ("BO_HOLDINGS")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
    
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''List of End of the day underlying Trades for holdings for the clients and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_bo_Ul_Trades(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("BO_UI_TRADES"))[0].url
            apiName = utilClass.read_property ("BO_UI_TRADES")
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)


'''This method allows you to logout from the application and it will check authorization token,
input request validation and manipulation,output response validation and manipulation method calls,Audit storage method call and check input encryption,
response decryption ,rsa algorithm'''
@api_view(["POST"])
def get_logout(request):
    utilClass=UtilClass()
    logger.info(utilClass.read_property("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    userId=''
    try:
        if request.method == utilClass.read_property ('METHOD_TYPE'):
            ipAddress=utilClass.get_client_ip(request)
            url = apiHomeDict.get(utilClass.read_property("LOG_OUT"))[0].url
            apiName=utilClass.read_property("LOG_OUT")
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
            jKey = requestObj.get_jkey(publicKey4Pem)
            bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,apiHomeDict,ipAddress)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, apiHomeDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, inputDict)
            if utilClass.read_property("STATUS") in result and result[utilClass.read_property("STATUS")]==utilClass.read_property("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,apiHomeDict,userId)
                logger.info(utilClass.read_property("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,apiHomeDict,ipAddress)
            jsonData = json.dumps(result)
            publicKey4 = requestObj.import_key(publicKey4Pem)
            if(utilClass.read_property('ALGORITHM_TYPE')=='RSA'):
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
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,apiHomeDict,successDict,failureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
            logger.info(utilClass.read_property("EXITING_METHOD"))
            return Response(output)
        
    except Exception as exception:
        logger.exception(exception)
        err=str(exception)
        output=validate.create_error_response(err)
        auditTrial.api_response_audit (requestId, output,apiName,apiHomeDict,userId)
        return Response(output)
    
    
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
    