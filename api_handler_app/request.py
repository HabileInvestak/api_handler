import base64
import hashlib
import json
import logging
import urllib
import urllib2

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

from utils import UtilClass


logger = logging.getLogger('api_handler_app.request.py')


'''This class is used to deal with request related public key,private key validation'''
class RequestClass():

    '''This method is used to generate key pair'''
    def generate_key_pair(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            randomGenerator = Random.new().read
            #print "Key size",read_property('KEY_SIZE')
            key = RSA.generate(int(utilClass.read_property('KEY_SIZE')), randomGenerator)
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return key


    '''This method is used to get publicKey2'''
    def get_public_key_pem(self,key):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            publicKey2PEM = key.publickey().exportKey(utilClass.read_property("PEM"))
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return publicKey2PEM
    
    
    '''This method is used to get privateKey2'''
    def get_private_key_pem(self,key):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            privateKey2PEM = key.exportKey()
        except Exception as exception:
            raise exception           
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return privateKey2PEM
    
    
    '''This method is used to get import_key'''
    def import_key(self,key_pem):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            key = RSA.importKey(key_pem)
            # cipher = PKCS1_v1_5.new(key)
        except Exception:
            raise ValueError(utilClass.read_property("INVALID_TOKEN")) 
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return key
    
    
    '''This method is used to get jKey'''
    def get_jkey(self,decoded_public_key):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            hashObject = hashlib.sha256(decoded_public_key)
            jKey = hashObject.hexdigest()
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return jKey
    
    
    '''This method is used to encode a userId'''
    def get_jsessionid(self,user_id):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            jSessionId = self.b64_encode(user_id)
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return jSessionId


    '''This method is used to send a request to TSO server and get response'''
    def send_request(self,bodyContent, url, authorization, userId, tomcatCount, jKey, jData):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if utilClass.is_not_blank(bodyContent):
                jSessionId = self.get_jsessionid(userId)
                tomcatCount = self.get_tomcat_count(tomcatCount)
                if utilClass.is_not_blank(jSessionId):
                    url = url + "?jsessionid=" + jSessionId.strip()
                if utilClass.is_not_blank(tomcatCount):
                    url = url + "." + tomcatCount.strip()
                
                values = {'jKey': jKey,
                          'jData': jData}
                print "Before values",values
                data = urllib.urlencode(values)
                try:
                    req = urllib2.Request(url, data)
                    response = urllib2.urlopen(req)
                    thePage = response.read()
                    d = json.loads(thePage)
                except Exception:
                    raise ValueError(utilClass.read_property("INVALID_TARGET_URL"))
                logger.info(utilClass.read_property("EXITING_METHOD"))  
                print "@@@@@@@@@@@@@@@@@@@@@@"
                print d
                return d
            else:
                resp = requests.post(url)
                logger.info(utilClass.read_property("EXITING_METHOD"))  
                return resp.text
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
    
    
    '''This method is used to get cipher key'''
    def get_cipher(self,key):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            cipher = PKCS1_v1_5.new(key)
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return cipher
    
    
    '''This method is used to encrypt  data block'''
    def encrypt_block(self,key, data, start, end):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            data = data[start:end]
            cipher = self.get_cipher(key)
            encryptedData = cipher.encrypt(data)
            encodedData = self.b64_encode(encryptedData)
            replaceData = utilClass.replace_text(encodedData, "\n", "")
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return replaceData
    
    
    '''This method is used to encrypt a data'''
    def encrypt(self,data, key, key_size):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            bufferVar = ""
            numberOfBytes = ((int(utilClass.read_property ('KEY_SIZE')) / int(utilClass.read_property('BYTE_BOUNDARY'))) - int(utilClass.read_property('BYTE_DIFFERENCE')))
            start = 0
            end = numberOfBytes
            if (numberOfBytes > len(data)):
                end = len(data)
            bufferVar = bufferVar + self.encrypt_block(key, data, start, end)
            bufferVar = utilClass.append_data(bufferVar, "\n")#utilClass.read_property("SLASH_N")
            start = end
            end += numberOfBytes
            if (end > len(data)):
                end = len(data)
        
            while (end < len(data)):
                bufferVar = bufferVar + self.encrypt_block(key, data, start, end)
                bufferVar = utilClass.append_data(bufferVar, "\n")
                start = end
                end += numberOfBytes
                if (end > len(data)):
                    end = len(data)
            if (end - start > 0):
                bufferVar = bufferVar + self.encrypt_block(key, data, start, end)
                bufferVar = utilClass.append_data(bufferVar, "\n")
            bufferVar = self.b64_encode(bufferVar)
            bufferVar = utilClass.replace_text(bufferVar, "\n", "")
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return bufferVar
    
    
    '''This method is used to get decrypt data'''
    def decrypt(self,data, private_key):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            data = self.b64_decode(data)
            data = unicode(data, utilClass.read_property("UTF-8"))
            data = data.strip().split("\n")
            finalData = ""
            for tempData in data:
                tempData = self.b64_decode(tempData)
                cipher = self.get_cipher(private_key)
                tempData = cipher.decrypt(tempData, utilClass.read_property('UTF-8'))
                finalData = utilClass.append_data(finalData, tempData)
        except Exception as exception:
            raise exception           
        logger.info(utilClass.read_property("EXITING_METHOD"))      
        return finalData
    
    
    '''This method is used to get decode'''
    def b64_decode(self,data):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            decodedData = base64.b64decode(data)
        except Exception:
            raise ValueError(utilClass.read_property("INVALID_TOKEN"))      
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return decodedData
    
    
    '''This method is used to get encode'''
    def b64_encode(self,data):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            encodedData = data.encode(utilClass.read_property("BASE64"))
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return encodedData
    
    
    
    
    '''This method is used to get tomcat count'''
    def get_tomcat_count(self,tomcatCount):
        # tomcat_count=''
        return tomcatCount    
