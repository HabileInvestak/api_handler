from properties.p import Property

import logging
import json
import hashlib

logger = logging.getLogger('api_handler_app.utils.py')
prop=Property()
prop_obj = prop.load_property_files('E:\\Investak\\investak.properties')


class UtilClass():


    ''' This method will read the configuration values from property file'''
    def readProperty(self,name):
        #logger.info(readProperty("ENTERING_METHOD"))
        try:
            data=prop_obj.get(name)
            #logger.info(readProperty("EXITING_METHOD"))
            return data
        except Exception as e:
            logger.exception(e)
            raise Exception(e)        


    '''This method is used to create PasswordHash'''
    def PasswordHash(self,jsonObject):
        
        logger.info(self.readProperty("ENTERING_METHOD"))        
        data={}
        try:
            for key in jsonObject:
                value = jsonObject[key]
                if key == self.readProperty ('PASSWORD'):
                    value = self.password_hash (value)
                data[key] = value
        except Exception as e:
            raise e        
        logger.info(self.readProperty("EXITING_METHOD"))      
        return data


    '''This method will check whether the given input is in JSON format or not'''
    def checkJson(self,text):
        
        logger.info(self.readProperty("ENTERING_METHOD"))
        result = False
        try:
            json.loads(text)
            result = True 
        except Exception:
            result = False
        logger.info(self.readProperty("EXITING_METHOD"))  
        return result

    
    '''This method will check whether the given string is not Blank or Blank'''
    def isNotBlank(self,myString):
        
        logger.info(self.readProperty("ENTERING_METHOD"))
        try:
            if myString and (part.strip() for part in myString):
                # myString is not None AND myString is not empty or blank
                logger.info(self.readProperty("EXITING_METHOD"))  
                return True
            # myString is None OR myString is empty or blank
        except Exception as e:
            raise e    
        logger.info(self.readProperty("EXITING_METHOD"))  
        return False

    
    '''This method will check whether the given string is Blank or not'''
    def isBlank(self,myString):
        
        logger.info(self.readProperty("ENTERING_METHOD"))
        try:
            if myString and (part.strip() for part in myString):
                # myString is not None AND myString is not empty or blank
                logger.info(self.readProperty("EXITING_METHOD"))  
                return False
                # myString is None OR myString is empty or blank
        except Exception as e:
            raise e   
        logger.info(self.readProperty("EXITING_METHOD"))  
        return True

    
    '''This method is used to replace a data'''
    def replace_text(self,orginal_data, old_text, new_text):
        
        logger.info(self.readProperty("ENTERING_METHOD"))        
        try:
            orginal_data = orginal_data.replace(old_text, new_text)
        except Exception as e:
            raise e   
        logger.info(self.readProperty("EXITING_METHOD"))  
        return orginal_data
    
    
    '''This method is used to add data'''
    def append_data(self,original_text, append_text):
        
        logger.info(self.readProperty("ENTERING_METHOD"))
        try:
            original_text = original_text + append_text
        except Exception as e:
            raise e   
        logger.info(self.readProperty("EXITING_METHOD"))  
        return original_text

    
    '''This method is used to create PasswordHash'''
    def password_hash(self,password):
        
        logger.info(self.readProperty("ENTERING_METHOD"))
        try:
            for num in range(0, 999):
                password = hashlib.sha256(password).digest()
            password_hash = hashlib.sha256(password).hexdigest()
        except Exception as e:
            raise e   
        logger.info(self.readProperty("EXITING_METHOD"))
        return password_hash