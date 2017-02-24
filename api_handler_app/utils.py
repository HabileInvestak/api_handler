from datetime import datetime
import hashlib
import json
import logging
import random

from api_handler_app.return_all_dict import ReturnAllDict


logger = logging.getLogger('api_handler_app.utils.py')

#propObj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
#propObj = prop.load_property_files('E:\\Investak\\investak.properties')

'''This class is used to deal with utility function'''
class UtilClass():
    
    ''' This method is used to fetch client ip address from request'''
    def get_client_ip(self,request):
        logger.info(self.read_property("ENTERING_METHOD"))
        try:
            xForwardedFor = request.META.get('HTTP_X_FORWARDED_FOR')
            if xForwardedFor:
                print "returning FORWARDED_FOR"
                ip = xForwardedFor.split(',')[-1].strip()
            elif request.META.get('HTTP_X_REAL_IP'):
                print "returning REAL_IP"
                ip = request.META.get('HTTP_X_REAL_IP')
            else:
                print "returning REMOTE_ADDR"
                ip = request.META.get('REMOTE_ADDR') 
        except Exception as exception:
            logger.exception(exception)
            raise Exception(exception)
        logger.info(self.read_property("EXITING_METHOD"))   
        return ip  
        

    ''' This method will read the configuration values from property file'''
    def read_property(self,name):
        try:
            returnAllDict = ReturnAllDict()
            allList = returnAllDict.return_dict()
            propObj = allList[6]
            data=propObj.get(name)
            return data
        except Exception as exception:
            logger.exception(exception)
            raise Exception(exception)        


    '''This method is used to create PasswordHash'''
    def password_hash(self,jsonObject):
        
        logger.info(self.read_property("ENTERING_METHOD"))        
        data={}
        try:
            for key in jsonObject:
                value = jsonObject[key]
                if key == self.read_property ('PASSWORD'):
                    value = self.password_hash_value (value)
                data[key] = value
        except Exception as exception:
            raise exception        
        logger.info(self.read_property("EXITING_METHOD"))      
        return data


    '''This method is used to create PasswordHash'''
    def generate_request_id(self,userId,apiName):
        
        logger.info(self.read_property("ENTERING_METHOD"))        
        try:
            dateTime = str(datetime.now ())
            randomNo=str(random.randint(1111,9999))
            requestId=userId+'_'+apiName+'_'+dateTime+'_'+randomNo
            print 'requestId',requestId
        except Exception as exception:
            raise exception        
        logger.info(self.read_property("EXITING_METHOD"))      
        return requestId


    '''This method will check whether the given input is in JSON format or not'''
    def check_json(self,text):
        
        logger.info(self.read_property("ENTERING_METHOD"))
        result = False
        try:
            json.loads(text)
            result = True 
        except Exception:
            result = False
        logger.info(self.read_property("EXITING_METHOD"))  
        return result

    
    '''This method will check whether the given string is not Blank or Blank'''
    def is_not_blank(self,myString):
        
        logger.info(self.read_property("ENTERING_METHOD"))
        try:
            if myString and (part.strip() for part in myString):
                # myString is not None AND myString is not empty or blank
                logger.info(self.read_property("EXITING_METHOD"))  
                return True
            # myString is None OR myString is empty or blank
        except Exception as exception:
            raise exception    
        logger.info(self.read_property("EXITING_METHOD"))  
        return False

    
    '''This method will check whether the given string is Blank or not'''
    def is_blank(self,myString):
        
        logger.info(self.read_property("ENTERING_METHOD"))
        try:
            if myString and (part.strip() for part in myString):
                # myString is not None AND myString is not empty or blank
                logger.info(self.read_property("EXITING_METHOD"))  
                return False
                # myString is None OR myString is empty or blank
        except Exception as exception:
            raise exception   
        logger.info(self.read_property("EXITING_METHOD"))  
        return True

    
    '''This method is used to replace a data'''
    def replace_text(self,orginalData, oldText, newText):
        
        logger.info(self.read_property("ENTERING_METHOD"))        
        try:
            orginalData = orginalData.replace(oldText, newText)
        except Exception as exception:
            raise exception   
        logger.info(self.read_property("EXITING_METHOD"))  
        return orginalData
    
    
    '''This method is used to add data'''
    def append_data(self,originalText, appendText):
        
        logger.info(self.read_property("ENTERING_METHOD"))
        try:
            originalText = originalText + appendText
        except Exception as exception:
            raise exception   
        logger.info(self.read_property("EXITING_METHOD"))  
        return originalText

    
    '''This method is used to create PasswordHash'''
    def password_hash_value(self,password):
        
        logger.info(self.read_property("ENTERING_METHOD"))
        try:
            for num in range(0, 999):
                password = hashlib.sha256(password).digest()
            passwordHash = hashlib.sha256(password).hexdigest()
        except Exception as exception:
            raise exception   
        logger.info(self.read_property("EXITING_METHOD"))
        return passwordHash