import json
import logging
import time

import requests

from api_handler_app.return_all_dict import ReturnAllDict
from utils import UtilClass


logger = logging.getLogger('api_handler_app.validate.py')

'''This class used to  validation and manipulation of All api Values'''
class Validate():
    
    '''This method used to check parameter value is mandatory or not.if mandatory paramter value is empty or null error message is added to error list'''
    def optional_validation(self,optional, paramValue, param):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        errorList = []
        errorMsg = ""
        try:
            print "optional_validation"
            if utilClass.is_blank(optional):
                pass
            elif(optional == utilClass.read_property('YES')):
                if utilClass.is_blank(paramValue) :
                    if paramValue is not None:
                        arrayValue = [param]
                        errorMsg = self.create_error_message (utilClass.read_property ("MANDATORY_FIELD"), arrayValue)
            if errorMsg:
                errorList.append (errorMsg)
            print "oprional validation end "
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorList
    
    
    '''This method used to check parameter value is string or not'''
    def is_string(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        errorMsg=''
        try:
            if paramValue:
                pass
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check parameter value is character or not if non character error message is added to error list'''
    def is_character(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue:
                errorMsg=''
                valueLength = len(paramValue)
                if (valueLength == 1):
                    pass
                else:
                    arrayValue = [param, dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check  parameter value is number or not, if non a number error message is added to error list'''
    def is_number(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue:
                logger.debug(paramValue)
                print 'paramValue',paramValue
                if(str(paramValue).isdigit()):
                    pass
                else:
                    arrayValue = [param, dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check  decimal or not, if non a decimal error message is added to error list'''
    def is_decimal(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue=='00.00':
                paramValue='0.00'
                logger.debug("paramValue replace"+paramValue)
            print 'paramValue',paramValue
            if paramValue and str(paramValue)!=utilClass.read_property("NA"):
                splitNum=str(paramValue).split('.', 1)
                if(str(paramValue).isdigit()):
                    pass
                elif (isinstance (json.loads (str(paramValue)), (float)) and str(splitNum[1]).isdigit() and str(abs(int(splitNum[0]))).isdigit ()):#-ve value replace to +ve value
                    pass
                else:
                    arrayValue = [param, dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
                
        except Exception:
            arrayValue = [param, dataType,validValues]
            errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check response is list or not,if non a list, error message is added to error list'''
    def is_list(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        try:
            if paramValue:
                listArray=jsonDict.get(validValues)
                logger.debug("listArray")
                logger.debug(listArray)
                if paramValue in listArray:
                    logger.debug("if")
                else:
                    logger.debug("else")#pass
                    arrayValue = [param, dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check parameter value is date time or not,if non a date time, error message is added to error list'''
    def is_date_time(self,paramValue,param, dataType,validValues,errorMessageTemplate,dictVar):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict= ReturnAllDict()
        allList = returnAllDict.return_dict()
        inputDict = allList[1]
        successDict=allList[2]
        try:
            if paramValue and dictVar==inputDict:
                date=self.validate_date_time_input (paramValue)
                if date:
                    pass
                else:
                    arrayValue = [param,dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_DATE_TIME"), arrayValue)
            
            elif paramValue!=utilClass.read_property ("NA") and dictVar==successDict:
                date=self.validate_date_time_success (paramValue)
                if date:
                    pass
                else:
                    arrayValue = [param,dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_DATE_TIME_SUCCESS"), arrayValue)
            
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check parameter value is date or not,if non a date error message is added to error list'''
    def is_date(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue :
                if paramValue!=utilClass.read_property ("NA"):
                    date=self.validate_date (paramValue)
                    if date:
                        pass
                    else:
                        arrayValue = [param,dataType,validValues]
                        errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception    
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return errorMsg
    
    
    '''This method used to check parameter value is time or not,if non a time, error message is added to error list'''
    def is_time(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue :
                if paramValue!=utilClass.read_property ("NA"):
                    date=self.validate_time(paramValue)
                    if date:
                        pass
                    else:
                        arrayValue = [param,dataType,validValues]
                        errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))     
        return errorMsg
    
    '''This method used to check parameter value is Url or not,if non a Url, error message is added to error list'''
    def is_url(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue:
                logger.debug("dataType="+str(dataType))
                if self.exist_Url(paramValue):
                    pass
                else:
                    arrayValue = [param, dataType,validValues]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check  holding apiName response is Json or not,if Json,it will check Json array sheet datatype,valid values validation,
    if error in data type,valid values validation error  message is added to error list'''
    def is_json_dictAndList(self,paramValue,param, dataType,jsonDict,validValues):
        utilClass=UtilClass()
        errorMsg=''
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        utilClass=UtilClass()
        try:
            for paramTemp,paramValueTemp in paramValue.items():
                errorMsgTemp=''
                logger.debug(paramValueTemp)
                logger.debug(jsonDict.get(validValues).get(paramTemp)[0].dataType)
                dataType=jsonDict.get(validValues).get(paramTemp)[0].dataType
                if (dataType == utilClass.read_property('STRING')):
                    errorMsgTemp=self.is_string(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                       
                elif (dataType == utilClass.read_property('CHARACTER')):
                    errorMsgTemp=self.is_character(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                      
                elif(dataType == utilClass.read_property('NUMBER')):
                    errorMsgTemp=self.is_number(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                        
                elif (dataType == utilClass.read_property('DECIMAL')):
                    errorMsgTemp=self.is_decimal(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                        
                elif (dataType == utilClass.read_property('LIST')):
                    errorMsgTemp=self.is_list(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                       
                elif (dataType == utilClass.read_property('DATE_TIME')):
                    errorMsgTemp=self.is_date_time(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    
                elif (dataType == utilClass.read_property ('URL')):
                    errorMsgTemp=self.is_url(paramValueTemp,paramTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                                    
                elif (dataType == utilClass.read_property ('SSBOETOD')):
                    errorMsgTemp=self.is_ssboetod(paramValueTemp,paramTemp, dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        errorMsg=errorMsg+errorMsgTemp
                logger.debug("errorMsg=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@"+errorMsg) 
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))                     
        return errorMsg
    
    
    '''This method used to check  holding api response is json or not,and it is check it is a list and dictionary response.
    if list it give one by one response to check json validation method call.if error message occur it is added to error list'''
    def is_json_Holding(self,paramValue,param, dataType,jsonDict,validValues):
        errorMsg=''
        errorMsgAll=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        utilClass=UtilClass()
        try:
            if paramValue:
                logger.debug("###############JSON")
                logger.debug("ValidValues")
                logger.debug(validValues)
                logger.debug("paramValue")
                logger.debug(paramValue)
                #logger.debug(jsonDict.get(validValues))
                if type(paramValue) is list:
                    for paramValue in paramValue:
                        errorMsg=self.is_json_dictAndList(paramValue,param, dataType,jsonDict,validValues)    
                        if errorMsg:
                            if errorMsgAll:
                                errorMsgAll=errorMsgAll+","+errorMsg
                            else:
                                errorMsgAll=errorMsgAll+errorMsg 
                                      
                else:
                    errorMsg=self.is_json_dictAndList(paramValue,param, dataType,jsonDict,validValues)                   
                    errorMsgAll=errorMsg                   
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsgAll
    
    
    '''This method used to check json or not,if Json,it will check Json array sheet all datatype,valid values validation,it will check multiple list and dictionary response
    if error in data type,valid values validation error  message is added to error list'''
    def is_json(self,paramValue,param, dataType,jsonDict,validValues):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        utilClass=UtilClass()
        try:
            if paramValue:
                logger.debug("###############JSON1")
                logger.debug("ValidValues")
                logger.debug(validValues)
                logger.debug("paramValue")
                logger.debug(paramValue)
                #logger.debug(jsonDict.get(validValues))
                for paramValueTemp in paramValue:
                    errorMsgTemp=''
                    logger.debug(paramValueTemp)
                    logger.debug(jsonDict.get(validValues).get(paramValueTemp)[0].dataType)
                    dataType=jsonDict.get(validValues).get(paramValueTemp)[0].dataType
                    validValuesInner=jsonDict.get(validValues).get(paramValueTemp)[0].validValues
                    if (dataType == utilClass.read_property('STRING')):
                        errorMsgTemp=self.is_string(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property('CHARACTER')):
                        errorMsgTemp=self.is_character(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif(dataType == utilClass.read_property('NUMBER')):
                        errorMsgTemp=self.is_number(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property('DECIMAL')):
                        errorMsgTemp=self.is_decimal(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property('LIST')):
                        errorMsgTemp=self.is_list(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property('DATE_TIME')):
                        errorMsgTemp=self.is_date_time(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property ('URL')):
                        errorMsgTemp=self.is_url(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                        else:
                            errorMsgTemp=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                            if errorMsgTemp:
                                if errorMsg:
                                    errorMsg=errorMsg+","+errorMsgTemp
                                else:
                                    errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property ('JSON')):
                        logger.debug("JSON2") 
                        logger.debug("ValidValues JSON2")
                        logger.debug(validValues)
                        logger.debug("paramValue JSON2")
                        logger.debug(paramValueTemp)
                        validValues1=jsonDict.get(validValues).get(paramValueTemp)[0].validValues
                        logger.debug("validValues JSON2")
                        logger.debug(validValues1)
                        paramValueTemp1=jsonDict.get(validValues1)
                        if paramValueTemp1:
                            #logger.debug(validValues1)
                            #logger.debug(paramValueTemp1)
                            logger.debug(jsonDict.get(validValues1))
                            for paramValueInnerTemp1 in paramValueTemp1:
                                errorMsgTemp=''
                                logger.debug("Inner paramValueTemp1")
                                logger.debug(paramValueInnerTemp1)
                                logger.debug(jsonDict.get(validValues1).get(paramValueInnerTemp1)[0].dataType)
                                logger.debug("Inner datatype")
                                dataType1=jsonDict.get(validValues1).get(paramValueInnerTemp1)[0].dataType
                                validValues1Inner=jsonDict.get(validValues1).get(paramValueInnerTemp1)[0].validValues
    
                                if (dataType1 == utilClass.read_property('STRING')):
                                    errorMsgTemp=self.is_string(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property('CHARACTER')):
                                    errorMsgTemp=self.is_character(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif(dataType1 == utilClass.read_property('NUMBER')):
                                    errorMsgTemp=self.is_number(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property('DECIMAL')):
                                    errorMsgTemp=self.is_decimal(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property('LIST')):
                                    errorMsgTemp=self.is_list(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property('DATE_TIME')):
                                    errorMsgTemp=self.is_date_time(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property ('URL')):
                                    errorMsgTemp=self.is_url(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                                    else:
                                        errorMsgTemp=self.valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                        if errorMsgTemp:
                                            if errorMsg:
                                                errorMsg=errorMsg+","+errorMsgTemp
                                            else:
                                                errorMsg=errorMsg+errorMsgTemp
                                elif (dataType1 == utilClass.read_property ('JSON')):
                                    logger.debug("JSON3")
                                    logger.debug("ValidValues JSON2")
                                    logger.debug(validValues+"->"+validValues1)
                                    logger.debug("paramValue JSON2")
                                    logger.debug(paramValueInnerTemp1)
                                    validValues2=jsonDict.get(validValues1).get(paramValueInnerTemp1)[0].validValues
                                    logger.debug("validValues JSON2")
                                    logger.debug(validValues2)
                                    paramValueTemp2=validValues2
                                    logger.debug(paramValueTemp2)
                                    paramValueTemp2=jsonDict.get(validValues2)
                                    logger.debug(validValues2)
                                    if paramValueTemp2:
                                        for paramValueInnerTemp2 in paramValueTemp2:
                                            errorMsgTemp=''
                                            logger.debug("Inner paramValueTemp1")
                                            logger.debug(paramValueInnerTemp2)
                                            logger.debug(jsonDict.get(validValues2).get(paramValueInnerTemp2)[0].dataType)
                                            dataType2=jsonDict.get(validValues2).get(paramValueInnerTemp2)[0].dataType
                                            validValues2Inner=jsonDict.get(validValues2).get(paramValueInnerTemp2)[0].validValues
                                            logger.debug("errorMsgTemp@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"+errorMsgTemp)
                                            if (dataType2 == utilClass.read_property('STRING')):
                                                errorMsgTemp=self.is_string(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif (dataType2 == utilClass.read_property('CHARACTER')):
                                                errorMsgTemp=self.is_character(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif(dataType2 == utilClass.read_property('NUMBER')):
                                                logger.debug("Inside number")
                                                errorMsgTemp=self.is_number(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        logger.debug("Inside error message")
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                        logger.debug("Inside after error message")
                                                    else:
                                                        logger.debug("Outside error message")
                                                        errorMsg=errorMsg+errorMsgTemp
                                                        logger.debug("Outside after error message")
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif (dataType2 == utilClass.read_property('DECIMAL')):
                                                errorMsgTemp=self.is_decimal(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif (dataType2 == utilClass.read_property('LIST')):
                                                errorMsgTemp=self.is_list(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif (dataType2 == utilClass.read_property('DATE_TIME')):
                                                errorMsgTemp=self.is_date_time(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                                            elif (dataType2 == utilClass.read_property ('URL')):
                                                errorMsgTemp=self.is_url(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                                else:
                                                    errorMsgTemp=self.valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                    if errorMsgTemp:
                                                        if errorMsg:
                                                            errorMsg=errorMsg+","+errorMsgTemp
                                                        else:
                                                            errorMsg=errorMsg+errorMsgTemp
                    elif (dataType == utilClass.read_property ('SSBOETOD')):
                        errorMsgTemp=self.is_ssboetod(paramValueTemp,paramValueTemp, dataType,validValues,"INVALID_DATATYPE_JSON")
                        if errorMsgTemp:
                            errorMsg=errorMsg+errorMsgTemp
                    logger.debug("errorMsg=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@"+errorMsg)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    '''This method used to check ssboetod or not'''
    def is_ssboetod(self,paramValue,param, dataType,validValues,errorMessageTemplate):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if paramValue:
                pass
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
        
                            
    '''This method used to check all data type validation and forward to corresponding data type validation method,
    if error message occur,it is added to error list'''
    def data_type_validation(self,dataType,paramValue,param,validValues,ApiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        errorList = []
        errorMsg=''
        #logger.debug("dataType="+param+"="+paramValue+"="+dataType)
        try:
            if (dataType == utilClass.read_property('STRING')):
                errorMsg=self.is_string(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property('CHARACTER')):
                errorMsg=self.is_character(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif(dataType == utilClass.read_property('NUMBER')):
                errorMsg=self.is_number(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property('DECIMAL')):
                errorMsg=self.is_decimal(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property('LIST')):
                errorMsg=self.is_list(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property('DATE_TIME')):
                errorMsg=self.is_date_time(paramValue,param,dataType,validValues,"INVALID_DATATYPE",dictVar)
            elif (dataType == utilClass.read_property ('URL')):
                errorMsg=self.is_url(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('JSON')):
                if(ApiName=='Holdings'):
                    errorMsg=self.is_json_Holding(paramValue,param, dataType,jsonDict,validValues)
                    logger.debug(errorMsg)
                else:
                    errorMsg=self.is_json(paramValue,param, dataType,jsonDict,validValues)
                    logger.debug(errorMsg)  
            elif (dataType == utilClass.read_property ('SSBOETOD')):
                errorMsg=self.is_ssboetod(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('DATE')):
                errorMsg=self.is_date(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('TIME')):
                errorMsg=self.is_ssboetod(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
            if errorMsg:
                errorList.append (errorMsg)
            logger.debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@="+errorMsg)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return errorList
    
    
    '''This method used to check url type validation,if not url it return false'''
    def exist_Url(self,path):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnValue=True
        try:
            requests.head (path)
            returnValue=True
        except Exception:
            returnValue=False   
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return returnValue
    
    
    '''This method used to validate date time format for Input Request,if not date time in input response it return false'''
    def validate_date_time_input(self,dateText):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            time.strptime(dateText, '%m/%d/%Y/%w/%H:%M:%S')
            date = True
        except ValueError:
            date = False
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return date
    
    
    '''This method used to validate date time format for success response,if not date time in success response it return false'''
    def validate_date_time_success(self,dateText):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if utilClass.read_property("HYPEN_DATE") in dateText:
                try:
                    time.strptime(dateText,'%d-%b-%Y %H:%M:%S')
                    date = True
                except ValueError:
                    date = False
            elif utilClass.read_property("SLASH") in dateText:
                try:
                    time.strptime(dateText,'%d/%m/%Y %H:%M:%S')
                    date = True
                except ValueError:
                    date = False
            else:
                date = False
        except ValueError:
            date = False
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return date
    
    
    '''This method used to validate date format for success response,if not date time in success response it return false'''
    def validate_date(self,dateText):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if utilClass.read_property("HYPEN_DATE") in dateText:
                try:
                    time.strptime(dateText,'%d-%b-%Y')
                    date = True
                except ValueError:
                    date = False
            elif utilClass.read_property("SLASH") in dateText:
                try:
                    time.strptime(dateText,'%d/%m/%Y')
                    date = True
                except ValueError:
                    date = False
            else:
                date = False
        except ValueError:
            date = False
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return date
   
   
    '''This method used to validate time format for success response,if not time in success response it return false'''
    def validate_time(self,dateText):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            time.strptime(dateText,'%H:%M:%S')
            date = True
        except ValueError:
            date = False
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return date
    
    
    '''This method will check the input field availability and compare length of input field to expected length
    if not input field in request and response it will create error message and it added to error list'''
    def validate_length_and_invalid_field(self,content,ApiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        isErrorAvailable=False
        #print dict.get(ApiName).get(ApiName)[0].parameter
        errorList=[]
        expectList=[]
        expectMsg=''
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        inputDict = allList[1]
        jsonDict = allList[4]
        try:
            for k, v in dictVar.items():
                if k == ApiName:
                    for k1, v1 in v.items():
                        logger.debug(k1)
                        for v2 in v1:
                            b = v2.parameter
                            expectList.append(b)
            logger.debug(expectList)
            expectLen=len (expectList)
            contentLen=len (content)
            logger.debug(content)
            if (expectLen != contentLen) and not dictVar==jsonDict and dictVar==inputDict: #<
                arrayValue = [expectLen,contentLen]
                expectMsg = self.create_error_message (utilClass.read_property ("EXPECTED_AVAILABLE_PARAMETERS"), arrayValue)
                errorList.append (expectMsg)
            if not errorList:
                print "content==================",content
                for param, v in content.items():
                    if (param in expectList):
                        pass
                    else:
                        arrayValue = [param]
                        errorMsg = self.create_error_message (utilClass.read_property ("INVALID_FIELD"), arrayValue)
                        errorList.append(errorMsg)
            if errorList:
                isErrorAvailable = True
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return isErrorAvailable,errorList
    
    
    '''This method will check the input for availability and format
     if input format in request is not Json it will create error message and it added to error list'''
    def check_input_body(self,content,ApiName,dictVar,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        errorAvailable=False
        errorList=[]
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        systemDict = allList[7]
        try:
            isInputAvailable=dictVar.get(ApiName)[0].inputApi
            if isInputAvailable==utilClass.read_property("YES"):
                if content:
                    dataContainerType=systemDict.get(sourceUrl)[0].dataContainerType
                    if(dataContainerType==utilClass.read_property ("JSON")):
                        result=utilClass.check_json(content)
                        if result==False:
                            arrayValue = [utilClass.read_property ("JSON")]
                            errorMsg = self.create_error_message (utilClass.read_property ("BODY_INPUT_INVALID_FORMAT"), arrayValue)
                            errorList.append (errorMsg)
                    else:
                        arrayValue = [utilClass.read_property ("JSON")]
                        errorMsg = self.create_error_message (utilClass.read_property ("BODY_INPUT_INVALID_FORMAT"), arrayValue)
                        errorList.append (errorMsg)           
                else:
                    arrayValue = []
                    errorMsg = self.create_error_message (utilClass.read_property ("BODY_INPUT_REQUIRED"), arrayValue)
                    errorList.append(errorMsg)
        
            else:
                if content:
                    arrayValue = []
                    errorMsg = self.create_error_message (utilClass.read_property ("BODY_INPUT_NOT_ALLOWED"), arrayValue)
                    errorList.append (errorMsg)
        
            if errorList:
                errorAvailable = True
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorAvailable,errorList


    '''This method used to check  parameter value for mandatory validation and data type,valid values validation method is called,
    if error message is occur in request and response it will added to error list'''
    def check_all_validate(self,content,ApiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        isErrorAvailale=False
        errorMsg=''
        errorList=[]
        errorListAll=[]
        returnAllDict = ReturnAllDict()
        expectList=[]
        allList = returnAllDict.return_dict()
        failureDict = allList[3]
        jsonDict = allList[4]
        try:
            a=0
            logger.debug("check_all_validate=====")
            #logger.debug("ApiName"+ApiName)
            for param, v in content.items():
                expectList.append(param)
            #logger.debug(expectList)
            for k, v in dictVar.items():
                if k == ApiName:
                    for k1, v1 in v.items():
                        logger.debug(k1)
                        for v2 in v1:
                            b = v2.parameter
                            #logger.debug("Parameter="+b)
                            #logger.debug(dictVar.get(b))
                            optional= dictVar.get(ApiName).get(b)[0].optional
                            #logger.debug("optional====="+optional) 
                            if (optional == utilClass.read_property('YES')):
                                #logger.debug("Yes="+b)
                                if (b in expectList):
                                    #logger.debug("In expect list")
                                    paramValue=content[b]
                                    #logger.debug(paramValue)
                                    if utilClass.is_blank(paramValue) :
                                        if paramValue is not None:
                                            arrayValue = [b]
                                            errorMsg = self.create_error_message (utilClass.read_property ("MANDATORY_FIELD"), arrayValue)
                                            if errorMsg:
                                                errorList.append (errorMsg)
                                else:
                                    arrayValue = [b]
                                    errorMsg = self.create_error_message (utilClass.read_property ("MANDATORY_FIELD"), arrayValue)
                                    errorList.append(errorMsg)
                                    #logger.debug(errorList)
            errorListAll.extend (errorList)
            #logger.debug("If not error list all")
            if not errorList:  
                logger.debug("No errorList")    
                logger.debug(content) 
                print 'content',content         
                for param, value in content.items():
                    a=a+1
                    logger.debug(a)
                    dataType= dictVar.get(ApiName).get(param)[0].dataType
                    logger.debug("param="+param)
                    logger.debug("dataType="+dataType)
                    validValues= dictVar.get(ApiName).get(param)[0].validValues
                    logger.debug("validValues="+validValues)
                    if not dictVar==failureDict and not dictVar==jsonDict:
                        errorList=self.data_type_validation(dataType,value,param,validValues,ApiName,dictVar)
                        errorListAll.extend (errorList)
                        if not errorList:
                            errorList = self.valid_values_validation (validValues, value, param,dataType)
                            errorListAll.extend (errorList)
                        errorList=[]
        
            if errorListAll:
                isErrorAvailale = True
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return isErrorAvailale,errorListAll
    
    
    '''This method used to check parameter value valid values validation,if not valid values of parameter value,
    it create error message it will added to error list'''
    def valid_values_validation(self,validValues,paramValue,param,dataType):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        logger.debug("!!!!!!!!!!!Inside Valid values")
        logger.debug(validValues)
        logger.debug(paramValue)
        logger.debug(param)
        logger.debug(dataType)
        errorList = []
        errorMsg=''
        try:
            #logger.debug("valid_values_validation="+validValues+"="+paramValue+"="+param+"="+dataType)
            logger.debug(dataType)
            if not (dataType == utilClass.read_property('JSON')):
                    if not (dataType == utilClass.read_property('LIST')):
                        logger.debug("==Inside valid values")
                        if utilClass.is_blank(validValues):
                            pass
                        else:
                            check=1
                            words = validValues.split (',')
                            for word in words:
                                if (str(paramValue)==word.strip()):
                                    check = 0
                            if utilClass.is_not_blank(paramValue) and check==0:
                                pass
                            else:
                                arrayValue=[param,validValues,paramValue]
                                logger.debug(arrayValue)
                                errorMsg=self.create_error_message(utilClass.read_property("INVALID_VALUE"),arrayValue)
                                logger.debug("After error message"+errorMsg)
                    if errorMsg:
                        errorList.append (errorMsg)
                    else:
                        logger.debug("No error message")
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return errorList


    '''This method used to check Json valid values validation,if not Json valid values of parameter value,
    it create error message it will added to error list'''
    def valid_values_validation_JSON(self,validValues,paramValue,param,dataType,validValuePath):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        logger.debug("!!!!!!!!!!!Inside Valid values")
        logger.debug(validValues)
        logger.debug(paramValue)
        logger.debug(param)
        logger.debug(dataType)
        errorMsg=''
        try:
            #logger.debug("valid_values_validation="+validValues+"="+paramValue+"="+param+"="+dataType)
            if not (dataType == utilClass.read_property('JSON')):
                if utilClass.is_blank(validValues):
                    pass
                else:
                    check=1
                    words = validValues.split (',')
                    for word in words:
                        if (str(paramValue).__contains__(word.strip())):
                            check = 0
                    if utilClass.is_not_blank(paramValue) and check==0:
                        pass
                    else:
                        arrayValue=[param,validValues,paramValue,validValuePath]
                        logger.debug(arrayValue)
                        errorMsg=self.create_error_message(utilClass.read_property("INVALID_VALUE_JSON"),arrayValue)
                        logger.debug("After error message"+errorMsg)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))    
        return errorMsg
    
    
    '''This method used to check validation and manipulation of all request and response of the parameter value,
    if data is list it will create one by one validation and manipulation.if error message is occur it will added to error list'''
    def validation_and_manipulation(self,jsonObject,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        result={}
        resultAll=[]
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        apiHomeDict=allList[0]
        inputDict = allList[1]
        successDict = allList[2]
        failureDict = allList[3]
        try:
            inputValidation=apiHomeDict.get(apiName)[0].inputValidation
            responseValidation=apiHomeDict.get(apiName)[0].responseValidation
            if type(jsonObject) is list:   # it is a List
                print 'list'
                print len(jsonObject)
                for response in jsonObject:
                    print response
                    stat=response.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        dictVar=successDict
                    else:
                        dictVar=failureDict
                    if(dictVar==inputDict and inputValidation==utilClass.read_property("YES")):
                        logger.debug("Validation parameter")
                        result = self.validation_parameter (response, apiName, dictVar)
                        if not result:
                            logger.debug("After manipulation_default")
                            response = self.manipulation_default (response, apiName, dictVar)
                            logger.debug("After validation_all")
                            result = self.validation_all (response, apiName, dictVar)
                        if not result:
                            logger.debug("After manipulation_transformation")
                            response = self.manipulation_transformation(response, apiName, dictVar)
                            result=response
                            logger.debug("result="+str(result))
                        if result:
                            resultAll.append(result)    
                    elif(dictVar==successDict and responseValidation==utilClass.read_property("YES")):
                        logger.debug("INSIDE SUCCESS")
                        result = self.validation_parameter (response, apiName, dictVar)
                        logger.debug(result)
                        if not result:
                            logger.debug("After validation_all in success")
                            logger.debug(response)
                            result = self.validation_all (response, apiName, dictVar)
                        logger.debug(result)
                        if not result:
                            logger.debug("After manipulation_transformation in success")
                            response = self.manipulation_transformation(response, apiName, dictVar)
                            result=response
                            logger.debug("result="+str(result))
                        if result:
                            resultAll.append(result)     
                    elif(dictVar==failureDict and responseValidation==utilClass.read_property("YES")):
                        result=response
                        result=self.add_list_msg(result)
                        resultAll.append(result) 
                    else:
                        result=response
                        resultAll.append(result) 
                return resultAll       
            else:            # it is a dictionary
                stat = jsonObject.get(utilClass.read_property('STATUS'))
                if not dictVar==inputDict:
                    if stat == utilClass.read_property ('OK'):
                        dictVar=successDict
                    elif stat == utilClass.read_property ('NOT_OK'):
                        dictVar=failureDict
                    else:
                        dictVar=successDict
                if(dictVar==inputDict and inputValidation==utilClass.read_property("YES")):
                    logger.debug("Validation parameter")
                    result = self.validation_parameter (jsonObject, apiName, dictVar)
                    if not result:
                        logger.debug("After manipulation_default")
                        jsonObject = self.manipulation_default (jsonObject, apiName, dictVar)
                        logger.debug("After validation_all")
                        result = self.validation_all (jsonObject, apiName, dictVar)
                    if not result:
                        logger.debug("After manipulation_transformation")
                        jsonObject = self.manipulation_transformation(jsonObject, apiName, dictVar)
                        result=jsonObject
                        logger.debug("result="+str(result))
                elif(dictVar==successDict and responseValidation==utilClass.read_property("YES")):
                    logger.debug("INSIDE SUCCESS")
                    result = self.validation_parameter (jsonObject, apiName, dictVar)
                    logger.debug(result)
                    if not result:
                        logger.debug("After validation_all in success")
                        logger.debug(jsonObject)
                        result = self.validation_all (jsonObject, apiName, dictVar)
                    logger.debug(result)
                    if not result:
                        logger.debug("After manipulation_transformation in success")
                        jsonObject = self.manipulation_transformation(jsonObject, apiName, dictVar)
                        result=jsonObject
                        logger.debug("result="+str(result))
                elif(dictVar==failureDict and responseValidation==utilClass.read_property("YES")):
                    result=jsonObject
                    result=self.add_list_msg(result)
                else:
                    result=jsonObject
                return result        
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        
    
    
    '''This method used to manipulate transformation of the parameter value,the transformation validation method is called
    and check transformation list name,source value is correct or not in list sheet if error create error response'''
    def manipulation_transformation(self,jsonObject, apiName, dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        failureDict = allList[3]
        jsonDict = allList[4]
        listDict = allList[5]
        expectList=[]
        expectListValue=[]
        errorList=[]
        errorMsg=''
        try:
            if jsonObject and  not dictVar==failureDict and not dictVar==jsonDict:
                for param, value in jsonObject.items():
                    dataType=dictVar.get(apiName).get(param)[0].dataType
                    transformation= dictVar.get(apiName).get(param)[0].transformation
                    if not dataType=='JSON':
                        for listName,listValue in listDict.items():
                            expectList.append(listName)
                            for sourceValue,remainValue in listValue.items():
                                if listName==transformation:
                                    expectListValue.append(sourceValue)
                        print 'expectList',expectList
                        #listValue= dictVar.get(apiName).get(param)[0].transformation
                        if transformation:
                            if transformation in expectList:
                                if utilClass.is_not_blank(value) and value in expectListValue:
                                    value = self.transformation_validation (transformation, value)
                                    jsonObject[param] = value
                                else:
                                    arrayValue=[value,transformation]
                                    logger.debug(arrayValue)
                                    errorMsg=self.create_error_message(utilClass.read_property("INVALID_TRANSFORMATION_SOURCE"),arrayValue)
                                    errorList.append(errorMsg)
                            else:
                                arrayValue=[transformation]
                                logger.debug(arrayValue)
                                errorMsg=self.create_error_message(utilClass.read_property("INVALID_TRANSFORMATION_LIST"),arrayValue)
                                errorList.append(errorMsg)
                    expectList=[]
                if errorList:
                    jsonObject = self.errorResponse (errorList, utilClass.read_property("NOT_OK"))           
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return jsonObject
    
    
    '''This method used to manipulate the parameter value to default value'''
    def manipulation_default(self,jsonObject, apiName, dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        inputDict = allList[1]
        try:
            if jsonObject and dictVar==inputDict:
                for param, value in jsonObject.items():
                    default= dictVar.get(apiName).get(param)[0].default
                    value = self.default_validation (default, value)
                    jsonObject[param]=value
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return jsonObject
    
    
    '''This method used to transform the parameter value from sheet'''
    def transformation_validation(self,transformation,paramValue):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        listDict = allList[5]
        try:
            if utilClass.is_blank(transformation):
                pass
            else:
                if utilClass.is_not_blank(paramValue):
                    transformation=listDict.get(transformation).get(paramValue)[0].targetValue
                    paramValue=transformation
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return paramValue
    
    
    '''This method used to check parameter value is blank default value is added when default value is there'''
    def default_validation(self,default,paramvalue):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if utilClass.is_blank(default):
                pass
            elif(utilClass.is_blank(paramvalue)):
                paramvalue=default
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return paramvalue
    
    
    '''This method will check the paramter value input for availability and format and validation body method is called.
    if error in list,it will call error response'''
    def chk_input_availability_and_format(self,jsonObject,apiName,dictVar,sourceUrl):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        result = {}
        try:
            # if (dict == apiHomeDict)
            param = self.check_input_body(jsonObject, apiName, dictVar,sourceUrl)
            isError = param[0]
            errorList = param[1]
            if (isError == True):
                result = self.errorResponse (errorList, utilClass.read_property("NOT_OK"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))        
        return  result
    
    
    '''This method used to check  parameter value validation and validation parameter method is called.
    if error in list,it will call error response method'''
    def validation_parameter(self,jsonObject,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        result = {}
        try:
            if jsonObject:
                param = self.validate_length_and_invalid_field (jsonObject, apiName, dictVar)
                isErrorAvailable = param[0]
                errorList = param[1]
                if (isErrorAvailable == True):
                    result = self.errorResponse (errorList, utilClass.read_property("NOT_OK"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))        
        return  result
    
    
    '''This method used to check all validation and validation all method is called.
    if error in list,it will call error response method'''
    def validation_all(self,jsonObject,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        result = {}
        try:
            if jsonObject:
                dataType = self.check_all_validate(jsonObject, apiName, dictVar)
                isErrorAvailable = dataType[0]
                errorList = dataType[1]
                if (isErrorAvailable == True):
                    result = self.errorResponse (errorList, utilClass.read_property("NOT_OK"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return  result
    
    
    '''This method is used to create error response from error list'''
    def errorResponse(self,errorList,stat):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        response_data = {}
        try:
            for error in errorList:
                response_data.setdefault(utilClass.read_property("ERROR_MSG"), [])
                response_data[utilClass.read_property("ERROR_MSG")].append(error)
                response_data[utilClass.read_property("STATUS")] = stat
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return response_data
    
    
    '''This method will create error message using property file and place holder'''
    def create_error_message(self,errorMessage,arrayValue):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            for index, item in enumerate (arrayValue):
                index = str(index)
                if type(item)==int:
                    item = str (item)
                errorMessage = errorMessage.replace ('['+index+']',item)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return  errorMessage
    
    
    '''This method is used to create error response'''
    def create_error_response(self,exception):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        response_data=''
        try:    
            stat = utilClass.read_property ("NOT_OK")
            errorList = []
            errorMsg = exception
            errorList.append(errorMsg)
            response_data=self.errorResponse(errorList,stat)
        except Exception as exception:
            print "Exception",exception
            raise exception        
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return response_data
    
    
    '''This method used to create error message in list where all error message is added to as a list'''
    def add_list_msg(self,result):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        listvar=[]
        try:
            if type(result) is list: #it is list
                eMsg=result[0].get(utilClass.read_property('ERROR_MSG'))
                listvar.append(eMsg)
                result[0][utilClass.read_property('ERROR_MSG')]=listvar
            else:      #it is dictionary
                eMsg=result.get(utilClass.read_property('ERROR_MSG'))
                if eMsg:
                    listvar.append(eMsg)
                    result[utilClass.read_property('ERROR_MSG')]=listvar
                else:
                    eMsg=result.get(utilClass.read_property('ERROR_CODE'))
                    if eMsg:
                        listvar.append(eMsg)
                        result[utilClass.read_property('ERROR_CODE')]=listvar
                    else:
                        eMsg=result.get(utilClass.read_property('ERROR'))
                        if eMsg:
                            listvar.append(eMsg)
                            result[utilClass.read_property('ERROR')]=listvar
                        else:
                            eMsg=result.get(utilClass.read_property('ERROR_MSG_SMALL'))
                            if eMsg:
                                listvar.append(eMsg)
                                result[utilClass.read_property('ERROR_MSG_SMALL')]=listvar
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return result