from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from properties.p import Property
from datetime import datetime
from rest_framework.views import exception_handler

import logging
import requests
import json
import hashlib
import urllib
import urllib2
import base64
import xlrd
import time


from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from rest_example.wsgi import ReturnAllDict
from restapp.models import Audit

e = ReturnAllDict()
AllList = e.returnDict()
ApiHomeDict = AllList[0]
InputDict = AllList[1]
SuccessDict = AllList[2]
FailureDict = AllList[3]
JsonDict = AllList[4]
ListDict = AllList[5]


logger = logging.getLogger('restapp.views.py')

prop = Property ()
#prop_obj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
prop_obj = prop.load_property_files ('C:\\Users\\Administrator\\Documents\\Investak\\working code\\investak.properties')  # ranjith

''' This method will read the configuration values from property file'''
def readProperty(name):
    
    try:
        data=prop_obj.get(name)
        return data
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        raise Exception(e)
    


'''Provides you with initial token for Login '''
@api_view([readProperty('METHOD_TYPE')])
def get_initial_token(request):
    logger.info(readProperty('112'))
    
    try:
        if request.method == readProperty('METHOD_TYPE'):
            content = request.body
            url = ApiHomeDict.get(readProperty('GET_INITIAL_KEY'))[0].url
            apiName = readProperty ("GET_INITIAL_KEY")
            print 'url',url
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            jsonObject = content
            userId=''
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
                userId=jsonObject.get('uid')
            data = validation_and_manipulation (jsonObject, apiName,InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit(request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response(data)
            print 'after validate '
            request_id=api_request_audit(request_id, data, apiName,userId)
            output = send_sequest(content, url, authorization, user_id="", tomcat_count="", jKey="", jData="")
            print 'output',output
            #d = json.loads(output)
            d = output
            initial_public_key1 = d[readProperty('PUBLIC_KEY')]
            tomcat_count = d[readProperty('TOMCAT_COUNT')]
            public_key1_pem = b64_decode(initial_public_key1)
            key_pair = generate_key_pair()
            public_key2_pem = get_public_key_pem(key_pair)
            private_key2_pem = get_private_key_pem(key_pair)
            public_key1 = import_key(public_key1_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(public_key2_pem, public_key1, 2048)
            else:
                raise Exception(readProperty('110'))    
            jKey = get_jkey(public_key1_pem)
            user_id = userId

            url = ApiHomeDict.get(readProperty('GET_PRE_AUTHENTICATION_KEY'))[0].url
            content=readProperty('YES')
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            stat = output.get (readProperty ('STATUS'))
            emsg = output.get (readProperty ('ERROR'))
            print 'tomcat_count ',tomcat_count
            initial_public_key3 = output[readProperty('PUBLIC_KEY3')]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_public_key3 = decrypt(initial_public_key3, private_key2)
            else:
                raise Exception(readProperty('110'))
            print readProperty('SLASH_N')
            initial_token = replace_text(b64_encode(private_key2_pem),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(decrypted_public_key3),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(tomcat_count),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(userId),"\n","")
            dictionary =tso_response_audit (request_id, output,apiName)
            if stat==readProperty('OK'):
                output = {readProperty('STATUS'):stat,readProperty('INITIAL_TOKEN'): initial_token,readProperty('TOMCAT_COUNT'):tomcat_count}
            else:
                output = {readProperty ('STATUS'): stat,readProperty ('ERROR'): emsg}
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
            
    except Exception as e:
        print "exception is",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
    

'''First step in login'''
@api_view([readProperty('METHOD_TYPE')])
def get_login_2fa(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOGIN_2FA"))[0].url
            apiName = readProperty ("LOGIN_2FA")
            print 'url',url
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            print 'userId',userId
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data=dataArray[0]
            BodyIn=dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn==True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)

            print 'after validate'
            request_id =api_request_audit (request_id, data, apiName,userId)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(userJSON,public_key3, 2048)
            else:
                raise Exception(readProperty('110'))    
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)       
        
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provide you with pre-authentication key for encryption'''
@api_view([readProperty ('METHOD_TYPE')])
def get_login(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)

            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3 = import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
   


'''Provide you with pre-authentication key for encryption'''
@api_view([readProperty ('METHOD_TYPE')])
def get_normal_login(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            encrypted_data = output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_data = decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty('110'))
            decrypted_json = json.loads(decrypted_data)
            print decrypted_json
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)   
        

'''Gives you information about client enabled data'''
@api_view([readProperty ('METHOD_TYPE')])
def get_default_login(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("DEFAULT_LOGIN"))[0].url
            apiName = readProperty ("DEFAULT_LOGIN")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
    
'''Authenticates the user with password'''
@api_view([readProperty ('METHOD_TYPE')])
def get_valid_pwd(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALID_PASSWORD"))[0].url
            apiName = readProperty("VALID_PASSWORD")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject,apiName,InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit(request_id,data,apiName)
                logger.info(readProperty('113'))
                return Response(data)
    
            data = PasswordHash(data)
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps (data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            #output=''
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary=tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    

'''Authenticates the answers in 2FA Q&A mode'''
@api_view([readProperty ('METHOD_TYPE')])
def get_valid_ans(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALID_ANSWER"))[0].url
            apiName = readProperty ("VALID_ANSWER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            print 'output accesstoken',output
            stat = output.get (readProperty ('STATUS'))
            print 'stat',stat
            emsg = output.get (readProperty ('ERROR_MSG'))
            encrypted_data=output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                 decrypted_data=decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty('110'))
            decrypted_json = json.loads(decrypted_data)
            print 'output accesstoken decrypted_json',decrypted_json
            dictionary =tso_response_audit (request_id, output,apiName)
            if decrypted_json[readProperty('STATUS')]==readProperty('OK'):
                access_token = replace_text(b64_encode(private_key2_pem), "\n", "") + "-" \
                               + replace_text(b64_encode(decrypted_json["sUserToken"]), "\n", "") + "-" \
                               + replace_text(b64_encode(tomcat_count), "\n", "") + "-" \
                               + replace_text(b64_encode(userId), "\n", "")
                decrypted_json[readProperty('ACCESS_TOKEN')] = access_token               
                #output = {readProperty('STATUS'): stat,readProperty('ACCESS_TOKEN'): access_token}
            else:
                decrypted_json = {readProperty('STATUS'): stat,readProperty('ERROR_MSG'): emsg}
            print 'output',decrypted_json   
            output = validation_and_manipulation (decrypted_json, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, decrypted_json,apiName)
            logger.info(readProperty('113'))
            return Response(decrypted_json)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you with account details'''
@api_view([readProperty ('METHOD_TYPE')])
def get_account_info(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ACCOUNT_INFO"))[0].url
            apiName = readProperty ("ACCOUNT_INFO")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            print 'userId',userId
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


@api_view([readProperty ('METHOD_TYPE')])
def get_login_by_pass(request):
    logger.info(readProperty('112'))
    logger.info(readProperty('113'))
    return ''

'''Gives retention types for the particular exchange'''
@api_view([readProperty ('METHOD_TYPE')])
def get_load_retention_type(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOAD_RETENSION_TYPE"))[0].url
            apiName = readProperty ("LOAD_RETENSION_TYPE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Check circuit limt for the order price'''
@api_view([readProperty ('METHOD_TYPE')])
def get_check_crkt_price_range(request):
    logger.info(readProperty('112'))
    try:  
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("CHECK_CORRECT_PRICE_RANGE"))[0].url
            apiName = readProperty ("CHECK_CORRECT_PRICE_RANGE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''GTD validations are done if retention is selected '''
@api_view([readProperty ('METHOD_TYPE')])
def get_validate_GTD(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALIDATE_GTD"))[0].url
            apiName = readProperty ("VALIDATE_GTD")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    

'''Validates Stop loss price'''
@api_view([readProperty ('METHOD_TYPE')])
def get_validate_SLM_price(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALIDATE_SLM_PRICE"))[0].url
            apiName = readProperty ("VALIDATE_SLM_PRICE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to place order for selected scrip'''
@api_view([readProperty ('METHOD_TYPE')])
def get_place_order(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("PLACE_ORDER"))[0].url
            apiName = readProperty ("PLACE_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view the placed orders and their status'''
@api_view([readProperty ('METHOD_TYPE')])
def get_order_book(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ORDER_BOOK"))[0].url
            apiName = readProperty ("ORDER_BOOK")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to modify open orders'''
@api_view([readProperty ('METHOD_TYPE')])
def get_modify_order(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("MODIFY_ORDER"))[0].url
            apiName = readProperty ("MODIFY_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output) 

'''Allows you to cancel an open order'''
@api_view([readProperty('METHOD_TYPE')])
def get_cancel_order(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("CANCEL_ORDER"))[0].url
            apiName = readProperty ("CANCEL_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view the order history for the Order.'''
@api_view([readProperty ('METHOD_TYPE')])
def get_order_history(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ORDER_HISTORY"))[0].url
            apiName = readProperty ("ORDER_HISTORY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view trade details'''
@api_view([readProperty('METHOD_TYPE')])
def get_trade_book(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("TRADE_BOOK"))[0].url
            apiName = readProperty ("TRADE_BOOK")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''This Allows user to view the holdings'''
@api_view([readProperty ('METHOD_TYPE')])
def get_holding(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("HOLDING"))[0].url
            apiName = readProperty ("HOLDING")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to view segment w ise RMS limits'''
@api_view([readProperty ('METHOD_TYPE')])
def get_limits(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LIMITS"))[0].url
            apiName = readProperty ("LIMITS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you w ith user details'''
@api_view([readProperty('METHOD_TYPE')])
def get_user_profile(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("USER_PROFILE"))[0].url
            apiName = readProperty ("USER_PROFILE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you with account details'''
@api_view([readProperty('METHOD_TYPE')])
def get_account_info(request):
    logger.info(readProperty('112'))
    try:
        if request.method ==readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ACCOUNT_INFO"))[0].url
            apiName = readProperty ("ACCOUNT_INFO")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Loads open order to set alerts based on trade.'''
@api_view([readProperty ('METHOD_TYPE')])
def get_open_orders(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("OPEN_ORDERS"))[0].url
            apiName = readProperty ("OPEN_ORDERS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            print 'output',output
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    



'''List of End of the Day holdings for clients'''
@api_view([readProperty('METHOD_TYPE')])
def get_bo_holdings(request):
    logger.info(readProperty('112'))
    try:
        if request.method ==readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("BO_HOLDINGS"))[0].url
            apiName = readProperty ("BO_HOLDINGS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''List of End of the day underlying Trades for holdings for the clients'''
@api_view([readProperty ('METHOD_TYPE')])
def get_bo_Ul_Trades(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("BO_UI_TRADES"))[0].url
            apiName = readProperty ("BO_UI_TRADES")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to logout from the application'''
@api_view([readProperty ('METHOD_TYPE')])
def get_logout(request):
    logger.info(readProperty('112'))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOG_OUT"))[0].url
            apiName=readProperty("LOG_OUT")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = validation_CheckInput (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty('113'))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty('113'))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty('110'))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty('113'))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=sendResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


def validation_and_manipulation(jsonObject,apiName,Dict):
    logger.info(readProperty('112'))
    data={}
    if not data:
        if Dict==InputDict:
            data = validation_Parameter (jsonObject, apiName, Dict)
            if not data:
                jsonObject = manipulation_Default (jsonObject, apiName, Dict)
                data = validation_All (jsonObject, apiName, Dict)#see
        if not data:
            if Dict==InputDict:
                jsonObject = manipulation_Transformation(jsonObject, apiName, Dict)
            data=jsonObject
            print 'Actual Data'
    logger.info(readProperty('113'))
    return data


def manipulation_Transformation(jsonObject, apiName, dict):
    logger.info(readProperty('112'))
    if jsonObject and  not dict==FailureDict and not dict==JsonDict:
        for param, value in jsonObject.items():
            transformation= dict.get(apiName).get(param)[0].transformation
            value = transformationValidation (transformation, value)
            jsonObject[param] = value
    logger.info(readProperty('113'))
    return jsonObject


def manipulation_Default(jsonObject, apiName, dict):
    logger.info(readProperty('112'))
    if jsonObject and dict==InputDict:
        for param, value in jsonObject.items():

            default= dict.get(apiName).get(param)[0].default
            value = defaultValidation (default, value)
            jsonObject[param]=value
    logger.info(readProperty('113'))
    return jsonObject


def transformationValidation(transformation,Paramvalue):
    logger.info(readProperty('112'))
    if isBlank(transformation):
        pass
    else:
        if isNotBlank(Paramvalue):
            transformation=ListDict.get(transformation).get(Paramvalue)[0].targetValue
            Paramvalue=transformation
        print 'transformation ', Paramvalue
    logger.info(readProperty('113'))
    return Paramvalue

def defaultValidation(default,Paramvalue):
    logger.info(readProperty('112'))
    if isBlank(default):
        pass
    elif(isBlank(Paramvalue)):
        Paramvalue=default
    logger.info(readProperty('113'))
    return Paramvalue


def validation_CheckInput(jsonObject,apiName,Dict):
    logger.info(readProperty('112'))
    data = {}
    BodyIn=True
    print 'validation_CheckInput'
    if (Dict == ApiHomeDict):
        print 'validation_CheckInput'
        Param = CheckInputBody(jsonObject, apiName, ApiHomeDict)
        checkParam = Param[0]
        print checkParam
        errorParam = Param[1]
        print errorParam
        stat = Param[2]
        print stat
        BodyIn = Param[3]
        print 'BodyIn',BodyIn
        if (checkParam == False):
            data = sendErrorRequesterror (errorParam, stat)
    logger.info(readProperty('113'))        
    return  data,BodyIn


def validation_Parameter(jsonObject,apiName,Dict):
    logger.info(readProperty('112'))
    data = {}
    if jsonObject:
        Param = CheckAllParameter (jsonObject, apiName, Dict)
        checkParam = Param[0]
        print checkParam
        errorParam = Param[1]
        print errorParam
        stat = Param[2]
        print stat
        if (checkParam == False):
            data = sendErrorRequesterror (errorParam, stat)
    logger.info(readProperty('113'))        
    return  data


def validation_All(jsonObject,apiName,Dict):
    logger.info(readProperty('112'))
    data = {}
    if jsonObject:
        dataType = checkAll (jsonObject, apiName, Dict)
        checkType = dataType[0]
        errorDataType = dataType[1]
        stat = dataType[2]
        if (checkType == False):
            data = sendErrorRequesterror (errorDataType, stat)
    logger.info(readProperty('113'))
    return  data

def sendErrorRequesterror(errorList,stat):
    logger.info(readProperty('112'))
    i=len(errorList)
    print i
    response_data = {}
    for v in errorList:

        response_data.setdefault(readProperty('ERROR_MSG'), [])
        response_data[readProperty('ERROR_MSG')].append(v)
        response_data[readProperty('STATUS')] = stat

    print 'response_data',response_data
    logger.info(readProperty('113'))
    return response_data

def checkAll(content,ApiName,dict):
    logger.info(readProperty('112'))
    check=True
    stat = ''
    errorMsg=''
    errorList=[]
    errorListAll=[]
    print 'content', content
    for param, value in content.items():
        dataType= dict.get(ApiName).get(param)[0].dataType
        validValues= dict.get(ApiName).get(param)[0].validValues
        print 'validValues',validValues
        if not dict==FailureDict and not dict==JsonDict:
            optional= dict.get(ApiName).get(param)[0].optional
            errorList = optionalValidation (optional, value, param)
            errorListAll.extend (errorList)
        if not errorList:
            errorList=dataTypeValidation(dataType,value,param,dict,validValues)
            errorListAll.extend (errorList)
        if not errorList:
            errorList = ValidValuesValidation (validValues, value, param,dataType)
            errorListAll.extend (errorList)
        errorList=[]

    if errorListAll:
        check = False
        stat  =readProperty('NOT_OK')
    print errorListAll
    logger.info(readProperty('113'))
    return check,errorListAll,stat



def ValidValuesValidation(validValues,paramValue,param,dataType):
    logger.info(readProperty('112'))
    errorList = []
    errorMsg=''
    if not (dataType == readProperty('JSON')):

        if isBlank(validValues):
            pass
        else:
            check=1
            words = validValues.split (',')
            for word in words:
                print 'word ',word
                print 'Paramvalue ',paramValue
                if (paramValue == word):
                    print 'yes'
                    check = 0
            print 'check ',check
            if isNotBlank(paramValue) and check==0:
                pass
            else:
                arrayValue=[param,validValues,paramValue]
                errorMsg=errorMsgCreate(readProperty('104'),arrayValue)
                print errorMsg
    print 'errorList validVal ',errorList
    if errorMsg:
        errorList.append (errorMsg)
    logger.info(readProperty('113'))    
    return errorList

def errorMsgCreate(string,arrayValue):
    logger.info(readProperty('112'))
    print 'string',string
    for index, item in enumerate (arrayValue):
        index = str(index)
        if type(item)==int:
            item = str (item)
        newstr = string.replace ('['+index+']',item)
        string = newstr
        print string
    logger.info(readProperty('113'))
    return  string

def optionalValidation(optional, Paramvalue, param):
    logger.info(readProperty('112'))
    errorList = []
    errorMsg = ''
    if isBlank(optional):
        pass
    elif(optional == readProperty('YES')):
        if isBlank(Paramvalue) :
            print '1'
            print '1'
            if Paramvalue is not None:
                print '2'
                print("param ",param,"-Paramvalue ",Paramvalue)
                arrayValue = [param]
                errorMsg = errorMsgCreate (readProperty ('105'), arrayValue)
                print errorMsg

    if errorMsg:
        errorList.append (errorMsg)
    logger.info(readProperty('113'))
    return errorList

def dataTypeValidation(dataType,Paramvalue,param,dict,validValues):
    logger.info(readProperty('112'))
    errorList = []
    errorMsg=''
    if not Paramvalue:
        #if (dataType == readProperty('STRING')):
        #    pass
        if (dataType == readProperty('CHARACTER')):
            Valuelen = len(Paramvalue)
            if (Valuelen == 1):
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                print errorMsg
        elif(dataType == readProperty('NUMBER')):
            if(Paramvalue.isdigit()):
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                print errorMsg
        elif (dataType == readProperty('DECIMAL')):
            try:    
                splitNum=Paramvalue.split('.', 1)
                print splitNum[1].isdigit () and splitNum[0].isdigit ()
                if(splitNum[1].isdigit() and splitNum[0].isdigit ()):
                    if (isinstance (json.loads (Paramvalue), (float))):
                        pass
                    else:
                        arrayValue = [param, dataType]
                        errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                        print 'hi1',errorMsg
                else:
                    arrayValue = [param, dataType]
                    errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                    print 'hi2',errorMsg
            except Exception as e:
                arrayValue = [param, dataType]
                errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)

        elif (dataType == readProperty('LIST')):
            print type (Paramvalue)
            print type(Paramvalue) is list
            if type(Paramvalue) is list:
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                print errorMsg

        elif (dataType == readProperty('DATE_TIME') and dict==InputDict):
            print type (Paramvalue)
            timestamp = time.strftime ('%m/%d/%Y/%w/%H:%M:%S')
            Date=validateDate (Paramvalue)
            print Date
            print timestamp
            if Date:
                pass
            else:
                arrayValue = [param,dataType]
                errorMsg = errorMsgCreate (readProperty ('103'), arrayValue)
                print errorMsg

        elif (dataType == readProperty ('URL')):

            if exist_Url(Paramvalue):
                print 'correct url'
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = errorMsgCreate (readProperty ('102'), arrayValue)
                print errorMsg

        elif (dataType == readProperty ('JSON')):
            data={}
            print 'JSON data type validation'
            print 'param Value ',Paramvalue
            print 'validValues ',validValues
            #data = validation_and_manipulation (jsonObject, apiName, InputDict)
            if type (Paramvalue) is list:
                Paramvalue = {k: '' for k in Paramvalue}
                print 'ParamValueDict',Paramvalue
                data=validation_and_manipulation(Paramvalue, validValues, JsonDict)
                print 'JSON data ',data
                if readProperty('STATUS') in data:
                    List = data.get (readProperty ('ERROR_MSG'))
                    for errorMsg in List:
                        errorList.append (errorMsg)
            else:
                print 'not list',Paramvalue
        # SSBOETOD need write

        if errorMsg:
            errorList.append (errorMsg)
        logger.info(readProperty('113'))    
        return errorList


def exist_Url(path):
    logger.info(readProperty('112'))
    r = requests.head (path)

    print r.status_code
    logger.info(readProperty('113'))
    return r.status_code == requests.codes.ok


def validateDate(date_text):
    logger.info(readProperty('112'))
    try:
        time.strptime(date_text, '%m/%d/%Y/%w/%H:%M:%S')
        Date = True
    except ValueError:
        Date = False
    logger.info(readProperty('113'))    
    return Date

def CheckAllParameter(content,ApiName,dict):
    logger.info(readProperty('112'))
    check=True
    #print dict.get(ApiName).get(ApiName)[0].parameter
    errorList=[]
    expectList=[]
    expectMsg=''
    stat = ''
    for k, v in dict.items():
        if k == ApiName:
            for k1, v1 in v.items():
                for v2 in v1:
                    b = v2.parameter
                    expectList.append(b.lower())
    expectLen=len (expectList)
    contentLen=len (content)
    print 'expectLen',expectLen
    print 'contentLen',contentLen
    if (expectLen != contentLen) and not dict==JsonDict:
        arrayValue = [expectLen,contentLen]
        expectMsg = errorMsgCreate (readProperty ('109'), arrayValue)
        errorList.append (expectMsg)
    print 'expectList',expectList
    print 'content ',content
    if not errorList:
        for param, v in content.items():
            print 'param',param
            if (param.lower() in expectList):
                pass
            else:
                arrayValue = [param]
                errorMsg = errorMsgCreate (readProperty ('101'), arrayValue)
                errorList.append(errorMsg)
    if errorList:
        stat = readProperty('NOT_OK')
        check = False
    print errorList
    print 'stat ',stat
    logger.info(readProperty('113'))
    return check,errorList,stat

def CheckInputBody(content,ApiName,dict):
    logger.info(readProperty('112'))
    print 'CheckInputBody'
    check=True
    print dict.get(ApiName)[0].inputApi
    print 'ApiName',ApiName
    errorList=[]
    expectMsg=''
    stat = ''
    BodyIn=True
    checkBody=dict.get(ApiName)[0].inputApi
    if checkBody==readProperty('CAPITAL_YES'):
        if content:
            key=''
            print key
            if(readProperty('INPUT_OUTPUT_TYPE')=='JSON'):
                key=checkJson(content)
                print 'key ',key
                if key=='0':
                    arrayValue = []
                    errorMsg = errorMsgCreate (readProperty ('108'), arrayValue)
                    errorList.append (errorMsg)
            else:
                raise Exception(readProperty('111'))            
        else:
            arrayValue = []
            errorMsg = errorMsgCreate (readProperty ('106'), arrayValue)
            errorList.append(errorMsg)

    else:
        BodyIn = False
        if content:
            print 'content',content
            arrayValue = []
            errorMsg = errorMsgCreate (readProperty ('107'), arrayValue)
            errorList.append (errorMsg)

    if errorList:
        stat = readProperty('NOT_OK')
        check = False
    print errorList
    print 'stat ',stat
    logger.info(readProperty('113'))
    return check,errorList,stat,BodyIn


def investak_request_audit(userId,request,apiName):
    logger.info(readProperty('112'))
    request_id=''
    dateNow = datetime.now ()
    logging = ApiHomeDict.get(apiName)[0].logging
    print 'logging',logging
    if (logging == readProperty ('CAPITAL_YES') and readProperty ('INVESTAK_API_AUDIT_ENABLE') == readProperty ('CAPITAL_YES')):
        Auditobj=Audit(user_id=userId, investak_request=request,investak_request_time_stamp=dateNow)
        Auditobj.save()
        request_id=Auditobj.request_id
    print 'investak_request_audit ',request
    print 'request_id ',request_id

    '''print 'dateNow ',dateNow
    Auditobj = Audit.objects.get(investak_request_time_stamp=dateNow)
    print 'Auditobj ', Auditobj.investak_request_time_stamp'''
    logger.info(readProperty('113'))
    return request_id

def api_request_audit(request_id,request,apiName,userId):
    logger.info(readProperty('112'))
    dateNow = datetime.now ()
    logging=ApiHomeDict.get(apiName)[0].logging
    if(logging==readProperty('CAPITAL_YES') and readProperty('API_TSO_AUDIT_ENABLE')==readProperty('CAPITAL_YES') and readProperty('INVESTAK_API_AUDIT_ENABLE')==readProperty('CAPITAL_YES')):
        obj, created = Audit.objects.update_or_create (
            request_id=request_id,
            defaults={readProperty('API_REQUEST'): request,readProperty('API_REQUEST_TIME_STAMP'):dateNow,readProperty('USER_ID'):userId},
        )
    else:
        Auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow)
        Auditobj.save ()
        request_id = Auditobj.request_id   
    print 'api_request_audit ',request
    logger.info(readProperty('113'))
    return request_id

def api_response_audit(request_id,request,apiName):
    logger.info(readProperty('112'))
    print 'TSO request',request
    dateNow = datetime.now ()
        #find json array
    if type(request) is list:
        print 'list'
        print len(request)
        for dict in request:
            print dict
            stat= dict.get (readProperty('STATUS'))
    else:
        print 'no list it is dict'
        stat= request.get (readProperty('STATUS'))
    if stat== readProperty ('OK'):
        api_status=readProperty ('SUCCESS')
    else:
        api_status = readProperty ('FAILURE')
    print  'api_status ', api_status
    logging = ApiHomeDict.get(apiName)[0].logging
    if (logging == readProperty ('CAPITAL_YES') and readProperty ('INVESTAK_API_AUDIT_ENABLE') == readProperty ('CAPITAL_YES')):
        obj, created = Audit.objects.update_or_create (
            request_id=request_id,
            defaults={readProperty('API_RESPONSE'): request,readProperty('API_RESPONSE_TIME_STAMP'):dateNow,readProperty('API_STATUS'):api_status},
        )
    print 'api_response_audit ',request

def tso_response_audit(request_id,request,apiName):
    print 'request',request 
    logger.info(readProperty('112'))
    dateNow = datetime.now ()
    if type(request) is list:
        print 'list'
        print len(request)
        for dict in request:
            print dict
            stat= dict.get (readProperty('STATUS'))
    else:
        print 'no list it is dict'
        stat= request.get (readProperty('STATUS'))
    if stat == readProperty ('OK'):
        tso_status = readProperty('SUCCESS')
        dictionary=SuccessDict
    else:
        tso_status = readProperty('FAILURE')
        dictionary=FailureDict
    print  'tso_status ',tso_status
    logging = ApiHomeDict.get(apiName)[0].logging
    if (logging == readProperty ('CAPITAL_YES') and readProperty ('API_TSO_AUDIT_ENABLE') == readProperty ('CAPITAL_YES')):
        obj, created = Audit.objects.update_or_create (
            request_id=request_id,
            defaults={readProperty('TSO_RESPONSE'): request,readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,readProperty('TSO_STATUS'):tso_status},
        )
    print 'tso_response_audit ',request
    logger.info(readProperty('113'))
    return dictionary


def password_hash(password):
    logger.info(readProperty('112'))
    for num in range(0, 999):
        password = hashlib.sha256(password).digest()
    password_hash = hashlib.sha256(password).hexdigest()
    logger.info(readProperty('113'))
    return password_hash


def send_sequest(body_content, url, authorization, user_id, tomcat_count, jKey, jData):
    logger.info(readProperty('112'))
    if isNotBlank(body_content):
        jsession_id = get_jsessionid(user_id)
        tomcat_count = get_tomcat_count(tomcat_count)
        if isNotBlank(jsession_id):
            url = url + "?jsessionid=" + jsession_id.strip()
        if isNotBlank(tomcat_count):
            url = url + "." + tomcat_count.strip()
        print "url="+url
        values = {'jKey': jKey,
                  'jData': jData}
        data = urllib.urlencode(values)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        the_page = response.read()
        d = json.loads(the_page)
        logger.info(readProperty('113'))  
        return d
    else:
        resp = requests.post(url)
        logger.info(readProperty('113'))  
        return resp.text


def get_cipher(key):
    logger.info(readProperty('112'))
    cipher = PKCS1_v1_5.new(key)
    logger.info(readProperty('113'))  
    return cipher


def encrypt_block(key, data, start, end):
    logger.info(readProperty('112'))
    data = data[start:end]
    cipher = get_cipher(key)
    encrypted_data = cipher.encrypt(data)
    encoded_data = b64_encode(encrypted_data)
    replace_data = replace_text(encoded_data, "\n", "")
    logger.info(readProperty('113'))  
    return replace_data


def encrypt(data, key, key_size):
    logger.info(readProperty('112'))
    buffer = ""
    number_of_bytes = ((int(readProperty ('KEY_SIZE')) / int(readProperty('BYTE_BOUNDARY'))) - int(readProperty('BYTE_DIFFERENCE')))
    start = 0
    end = number_of_bytes
    if (number_of_bytes > len(data)):
        end = len(data)
    buffer = buffer + encrypt_block(key, data, start, end)
    buffer = append_data(buffer, "\n")
    start = end
    end += number_of_bytes
    if (end > len(data)):
        end = len(data)

    while (end < len(data)):
        buffer = buffer + encrypt_block(key, data, start, end)
        buffer = append_data(buffer, "\n")
        start = end
        end += number_of_bytes
        if (end > len(data)):
            end = len(data)
    if (end - start > 0):
        buffer = buffer + encrypt_block(key, data, start, end)
        buffer = append_data(buffer, "\n")
    buffer = b64_encode(buffer)
    buffer = replace_text(buffer, "\n", "")
    logger.info(readProperty('113'))  
    return buffer


def replace_text(orginal_data, old_text, new_text):
    logger.info(readProperty('112'))
    orginal_data = orginal_data.replace(old_text, new_text)
    logger.info(readProperty('113'))  
    return orginal_data


def append_data(original_text, append_text):
    logger.info(readProperty('112'))
    original_text = original_text + append_text
    logger.info(readProperty('113'))  
    return original_text


def decrypt(data, private_key):
    logger.info(readProperty('112'))
    data = b64_decode(data)
    data = unicode(data, "utf-8")
    data = data.strip().split("\n")
    final_data = ""
    for temp_data in data:
        temp_data = b64_decode(temp_data)
        cipher = get_cipher(private_key)
        temp_data = cipher.decrypt(temp_data, 'utf-8')
        final_data = append_data(final_data, temp_data)
    logger.info(readProperty('113'))      
    return final_data


def b64_decode(data):
    logger.info(readProperty('112'))
    decoded_data = base64.b64decode(data)
    logger.info(readProperty('113'))  
    return decoded_data


def b64_encode(data):
    logger.info(readProperty('112'))
    encoded_data = data.encode("base64")
    logger.info(readProperty('113'))  
    return encoded_data


def generate_key_pair():
    logger.info(readProperty('112'))
    random_generator = Random.new().read
    #print "Key size",readProperty('KEY_SIZE')
    key = RSA.generate(int(readProperty('KEY_SIZE')), random_generator)
    logger.info(readProperty('113'))  
    return key


def get_public_key_pem(key):
    logger.info(readProperty('112'))
    publicKey2_PEM = key.publickey().exportKey("PEM")
    logger.info(readProperty('113'))  
    return publicKey2_PEM


def get_private_key_pem(key):
    logger.info(readProperty('112'))
    privateKey2_PEM = key.exportKey()
    logger.info(readProperty('113'))  
    return privateKey2_PEM


def import_key(key_pem):
    logger.info(readProperty('112'))
    key = RSA.importKey(key_pem)
    # cipher = PKCS1_v1_5.new(key)
    logger.info(readProperty('113'))  
    return key


def get_jkey(decoded_public_key):
    logger.info(readProperty('112'))
    hash_object = hashlib.sha256(decoded_public_key)
    jKey = hash_object.hexdigest()
    logger.info(readProperty('113'))  
    return jKey


def get_jsessionid(user_id):
    logger.info(readProperty('112'))
    jSessionId = b64_encode(user_id)
    logger.info(readProperty('113'))  
    return jSessionId


def get_tomcat_count(tomcat_count):
    # tomcat_count=''
    return tomcat_count


def decrtpt_data():
    encrypted_data = ''
    return encrypted_data;


def data_type(data, datatype):
    return ''


def valid_values(data, valid_values):
    return ''


def optional(data, is_optional):
    return ''


def default(data, is_default):
    return ''


def transformation(data, transform_value):
    return ''


def isBlank(myString):
    logger.info(readProperty('112'))
    if myString and (part.strip() for part in myString):
        # myString is not None AND myString is not empty or blank
        logger.info(readProperty('113'))  
        return False
    # myString is None OR myString is empty or blank
    logger.info(readProperty('113'))  
    return True


def isNotBlank(myString):
    logger.info(readProperty('112'))
    if myString and (part.strip() for part in myString):
        # myString is not None AND myString is not empty or blank
        logger.info(readProperty('113'))  
        return True
    # myString is None OR myString is empty or blank
    logger.info(readProperty('113'))  
    return False


def checkJson(text):
    logger.info(readProperty('112'))
    key = '1'
    print 'checkJson1'
    try:
        print 'checkJson2'
        print text
        abc = json.loads(text)
        print 'checkJson3',abc
        logger.info(readProperty('113'))  
        return key
    except Exception as e:
        print('invalid json: %s' % e)
        key='0'
        logger.info(readProperty('113'))  
        return key


def PasswordHash(jsonObject):
    logger.info(readProperty('112'))
    data={}
    for key in jsonObject:
        value = jsonObject[key]
        if key == readProperty ('PASSWORD'):
            value = password_hash (value)
        data[key] = value
    logger.info(readProperty('113'))      
    return data
    
def sendResponse(e):  
    logger.info(readProperty('112'))      
    stat = readProperty ('NOT_OK')
    errorList = []
    errorMsg = e
    print errorMsg
    errorList.append(errorMsg)
    response_data=sendErrorRequesterror(errorList,stat)
    logger.info(readProperty('113'))  
    return response_data    