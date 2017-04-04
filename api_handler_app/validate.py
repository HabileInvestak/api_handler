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
            if utilClass.is_blank(str(optional)):
                pass
            elif(optional == utilClass.read_property('YES')):
                if utilClass.is_blank(str(paramValue)) :
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
                    arrayValue = [param, dataType,validValues,paramValue]
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
                if(str(abs(int(paramValue))).isdigit()):
                    pass
                else:
                    arrayValue = [param, dataType,validValues,paramValue]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception:
            arrayValue = [param, dataType,validValues,paramValue]
            errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
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
            paramValue = str(paramValue).replace(',', '')
            paramValue = str(paramValue).replace(" ", "")
            print 'paramValue',paramValue
            if paramValue and str(paramValue)!=utilClass.read_property("NA"):
                splitNum=str(paramValue).split('.', 1)
                if(str(paramValue).isdigit()):
                    pass
                elif (isinstance (json.loads (str(paramValue)), (float)) and str(splitNum[1]).isdigit() and str(abs(int(splitNum[0]))).isdigit ()):#-ve value replace to +ve value
                    pass
                else:
                    arrayValue = [param, dataType,validValues,paramValue]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
                
        except Exception:
            arrayValue = [param, dataType,validValues,paramValue]
            errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check response is list or not,if non a list, error message is added to error list'''
    def is_list(self,paramValue,param, dataType,validValues,dictVar,ApiName,content):
        errorMsg=''
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        result=[]
        missingList=[]
        expectList=[]
        warningResponse={}
        try:
            if paramValue:
                for k, v in jsonDict.items():
                    if k == validValues:
                        for k1, v1 in v.items():
                            logger.debug(k1)
                            print k1
                            print v1
                            for v2 in v1:
                                b = v2.parameter
                                expectList.append(b)
                for contentParam in paramValue:
                    if (contentParam in expectList):
                        pass
                    else:
                        arrayValue = [str(contentParam),str(validValues)]
                        errorMsg = self.create_error_message (utilClass.read_property ("EXTRA_FIELD_MSG_LIST"), arrayValue)
                        #errorMsg=str(contentParam)+" "+utilClass.read_property("EXTRA_FIELD_MSG")  
                        missingList.append(errorMsg)
                if missingList:
                    missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)
            else: 
                arrayValue = [str(validValues)]
                errorMsg = self.create_error_message (utilClass.read_property ("EMPTY_LIST"), arrayValue)  
                missingList.append(errorMsg)
                missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return ""
    
    
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
                    arrayValue = [param,dataType,validValues,paramValue]
                    errorMsg = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_DATE_TIME"), arrayValue)
            
            elif paramValue!=utilClass.read_property ("NA") and dictVar==successDict:
                date=self.validate_date_time_success (paramValue)
                if date:
                    pass
                else:
                    arrayValue = [param,dataType,validValues,paramValue]
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
                        arrayValue = [param,dataType,validValues,paramValue]
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
                        arrayValue = [param,dataType,validValues,paramValue]
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
                    arrayValue = [param, dataType,validValues,paramValue]
                    errorMsg = self.create_error_message (utilClass.read_property (errorMessageTemplate), arrayValue)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return errorMsg
    
    
    '''This method used to check  holding apiName response is Json or not,if Json,it will check Json array sheet datatype,valid values validation,
    if error in data type,valid values validation error  message is added to error list'''
    def is_json_list_validate(self,paramValue,param, dataType,jsonDict,validValues,dictVar,ApiName,content):
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
                logger.debug(paramTemp)
                logger.debug(paramValueTemp)
                logger.debug(jsonDict.get(validValues).get(paramTemp)[0].dataType)
                dataType=jsonDict.get(validValues).get(paramTemp)[0].dataType
                validValuesInner=jsonDict.get(validValues).get(paramTemp)[0].validValues
                errorList=self.data_type_validation(dataType,paramValueTemp,paramTemp,validValuesInner,ApiName,jsonDict,content)
                if errorList:
                    for errorMsgTemp in errorList:
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                else:
                    errorMsgValid=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramTemp,dataType,validValues)
                    if errorMsgValid:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgValid
                        else:
                            errorMsg=errorMsg+errorMsgValid
                logger.debug("errorMsg=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@"+errorMsg) 
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))                     
        return errorMsg
    
    
    
    '''This method used to check  holding apiName response is Json or not,if Json,it will check Json array sheet datatype,valid values validation,
    if error in data type,valid values validation error  message is added to error list'''
    def is_json_validate(self,paramValue,param, dataType,jsonDict,validValues,dictVar,ApiName,content):
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
                logger.debug(paramTemp)
                logger.debug(paramValueTemp)
                logger.debug(jsonDict.get(validValues).get(paramTemp)[0].dataType)
                dataType=jsonDict.get(validValues).get(paramTemp)[0].dataType
                validValuesInner=jsonDict.get(validValues).get(paramTemp)[0].validValues
                errorList=self.data_type_validation(dataType,paramValueTemp,paramTemp,validValuesInner,ApiName,jsonDict,content)
                if errorList:
                    for errorMsgTemp in errorList:
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                else:
                    errorMsgValid=self.valid_values_validation_JSON(validValuesInner,paramValueTemp,paramTemp,dataType,validValues)
                    if errorMsgValid:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgValid
                        else:
                            errorMsg=errorMsg+errorMsgValid
                logger.debug("errorMsg=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@"+errorMsg) 
        except Exception as exception:
            raise exception   
        logger.info(utilClass.read_property("EXITING_METHOD"))                     
        return errorMsg
    
    
    '''This method used to check  holding api response is json list or not,and it is check it is a list and dictionary response.
    if list it give one by one response to check json validation method call.if error message occur it is added to error list'''
    def is_json_list(self,paramValue,param, dataType,validValues,dictVar,ApiName,content):
        errorMsg=''
        errorMsgAll=''
        warningResponse={}
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        utilClass=UtilClass()
        result=[]
        try:
            if paramValue:
                logger.debug("###############JSON")
                logger.debug("ValidValues")
                logger.debug(validValues)
                logger.debug("paramValue")
                logger.debug(paramValue)
                #logger.debug(jsonDict.get(validValues))
                #if type(paramValue) is list:
                print len(paramValue)
                for paramValue in paramValue:
                    invalidParam = self.validate_length_and_invalid_field (paramValue, validValues, jsonDict)
                    isErrorAvailable = invalidParam[0]
                    missingList = invalidParam[1]
                    invalidDict = invalidParam[2]
                    if invalidDict:
                        paramValue=self.remove_warning_list_parameter(paramValue,invalidDict)
                        warningResponse=self.create_warning_response(invalidDict,jsonDict,content,validValues)
                    if missingList:   
                        missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)
                    if not missingList and not utilClass.read_property("ERROR_MSG") in content:#and not invalidDict  and not utilClass.read_property("WARNING_MESSAGE") in content:    
                        errorMsg=self.is_json_list_validate(paramValue,param, dataType,jsonDict,validValues,dictVar,validValues,content)    
                        if errorMsg:
                            if errorMsgAll:
                                arrayValue = [errorMsgAll,errorMsg,validValues]
                                errorMsgAll = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_VALUE_JSON_ARRAY_EXIST"), arrayValue)
                                #errorMsgAll=errorMsgAll+","+errorMsg+" in "+validValues+" Json Array Sheet"
                            else:
                                arrayValue = [errorMsgAll,errorMsg,validValues]
                                errorMsgAll = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_VALUE_JSON_ARRAY_NEW"), arrayValue)
                                #errorMsgAll=errorMsgAll+errorMsg+" in "+validValues+" Json Array Sheet"          
            if errorMsgAll:
                missingList.append(errorMsgAll)
                missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return ""#errorMsgAll
    
    
    '''This method used to check  holding api response is json  or not,and it is check it is a list and dictionary response.
    if list it give one by one response to check json validation method call.if error message occur it is added to error list'''
    def is_json(self,paramValue,param, dataType,validValues,dictVar,ApiName,content):
        errorMsg=''
        errorMsgAll=''
        warningResponse={}
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        utilClass=UtilClass()
        result=[]
        try:
            if paramValue:
                logger.debug("###############JSON")
                logger.debug("ValidValues")
                logger.debug(validValues)
                logger.debug("paramValue")
                logger.debug(paramValue)
                invalidParam = self.validate_length_and_invalid_field (paramValue, validValues, jsonDict)
                isErrorAvailable = invalidParam[0]
                missingList = invalidParam[1]
                invalidDict = invalidParam[2]
                if invalidDict:
                    paramValue=self.remove_warning_list_parameter(paramValue,invalidDict)
                    warningResponse=self.create_warning_response(invalidDict,jsonDict,content,validValues)
                if missingList:   
                    missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)
                if not missingList and not utilClass.read_property("ERROR_MSG") in content:#not invalidDict and  and not utilClass.read_property("WARNING_MESSAGE") in content:   
                    errorMsg=self.is_json_validate(paramValue,param, dataType,jsonDict,validValues,dictVar,validValues,content)                   
                    if errorMsg:
                        if errorMsgAll:
                            arrayValue = [errorMsgAll,errorMsg,validValues]
                            errorMsgAll = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_VALUE_JSON_ARRAY_EXIST"), arrayValue)
                            #errorMsgAll=errorMsgAll+","+errorMsg+" in "+validValues+" Json Array Sheet"
                        else:
                            arrayValue = [errorMsgAll,errorMsg,validValues]
                            errorMsgAll = self.create_error_message (utilClass.read_property ("INVALID_DATATYPE_VALUE_JSON_ARRAY_NEW"), arrayValue)
                            #errorMsgAll=errorMsgAll+errorMsg+" in "+validValues+" Json Array Sheet"   
                    
                    #errorMsgAll=errorMsg+" in "+validValues+" Json Array Sheet"  
            if errorMsgAll:
                missingList.append(errorMsgAll)
                missingResponse=self.create_missing_response(result,content,missingList,warningResponse,jsonDict)               
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return ""#errorMsgAll
    
    
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
    def data_type_validation(self,dataType,paramValue,param,validValues,ApiName,dictVar,content):
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
            elif (dataType == utilClass.read_property('DATE_TIME')):
                errorMsg=self.is_date_time(paramValue,param,dataType,validValues,"INVALID_DATATYPE",dictVar)
            elif (dataType == utilClass.read_property ('URL')):
                errorMsg=self.is_url(paramValue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('LIST')):
                errorMsg=self.is_list(paramValue,param, dataType,validValues,dictVar,ApiName,content)
                logger.debug(errorMsg)
            elif (dataType == utilClass.read_property ('JSONLIST')):
                errorMsg=self.is_json_list(paramValue,param, dataType,validValues,dictVar,ApiName,content)
                logger.debug(errorMsg)
            elif (dataType == utilClass.read_property ('JSON')):
                errorMsg=self.is_json(paramValue,param, dataType,validValues,dictVar,ApiName,content)
                logger.debug(errorMsg)  
            elif (dataType == utilClass.read_property ('SSBOETOD')):
                errorMsg=self.is_ssboetod(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('DATE')):
                errorMsg=self.is_date(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.read_property ('TIME')):
                errorMsg=self.is_time(paramValue,param, dataType,validValues,"INVALID_DATATYPE")
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
        contentList=[]
        invalidDict={}
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        inputDict = allList[1]
        jsonDict = allList[4]
        successDict = allList[2]
        try:
            for k, v in dictVar.items():
                if k == ApiName:
                    for k1, v1 in v.items():
                        logger.debug(k1)
                        print k1
                        print v1
                        for v2 in v1:
                            b = v2.parameter
                            expectList.append(b)
            logger.debug(expectList)
            print 'expectList',expectList
            #expectLen=len (expectList)
            #contentLen=len (content)
            logger.debug(content)
            """if (expectLen != contentLen) and not dictVar==jsonDict and dictVar==inputDict: #<
                arrayValue = [expectLen,contentLen]
                expectMsg = self.create_error_message (utilClass.read_property ("EXPECTED_AVAILABLE_PARAMETERS"), arrayValue)
                errorList.append (expectMsg)"""
            
            if dictVar==inputDict:
                for key, value in content.items():
                    contentList.append(key)
                for cList in contentList:
                    if contentList.count(cList) > 1:
                        arrayValue = [cList]
                        errorMsg = self.create_error_message (utilClass.read_property ("DUPLICATE_KEY"), arrayValue)
                        errorList.append(errorMsg)
                        print "Duplicate key ",cList
                        contentList.remove(cList)
            if not errorList:
                for param in expectList:
                    if dictVar==jsonDict:
                        if param in content:
                            pass
                        else:
                            arrayValue = [param,ApiName]
                            errorMsg = self.create_error_message (utilClass.read_property ("MISSING_FIELD_JSON_ARRAY"), arrayValue)
                            errorList.append(errorMsg)
                    elif dictVar==successDict:
                        optional= dictVar.get(ApiName).get(param)[0].optional
                        print 'optional',optional
                        #if (optional == utilClass.read_property('YES')):
                        if param in content:
                            pass
                        elif(optional == utilClass.read_property('YES')):
                            arrayValue = [param]
                            errorMsg = self.create_error_message (utilClass.read_property ("MISSING_FIELD"), arrayValue)
                            errorList.append(errorMsg)
                        
                        #invalidDict[utilClass.read_property ("INVALID_FIELD")]=+" in "+validValues+" Json Array Sheet"
            
            #if not errorList:
                print "content==================",content
                if type(content) is list:
                    
                    """for param in content:
                        if (param in expectList):
                            pass
                        else:
                            if(dictVar==successDict or dictVar==jsonDict):
                                invalidDict.setdefault(utilClass.read_property ('WARNING_LIST'), []).append(param)
                                #invalidDict[utilClass.read_property ('WARNING_LIST')].append(param)
                            else:
                                arrayValue = [param]
                                errorMsg = self.create_error_message (utilClass.read_property ("INVALID_FIELD"), arrayValue)
                                errorList.append(errorMsg)"""
                else:
                    for param, value in content.items():
                        if (param in expectList):
                            pass
                        else:
                            if(dictVar==successDict or dictVar==jsonDict):
                                invalidDict[param]=value
                            else:
                                arrayValue = [param]
                                errorMsg = self.create_error_message (utilClass.read_property ("INVALID_FIELD"), arrayValue)
                                errorList.append(errorMsg)
            if errorList:
                isErrorAvailable = True
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return isErrorAvailable,errorList,invalidDict
    
    
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
    def check_all_validate(self,content,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        isErrorAvailale=False
        errorMsg=''
        errorList=[]
        errorListAll=[]
        returnAllDict = ReturnAllDict()
        expectList=[]
        allList = returnAllDict.return_dict()
        inputDict=allList[1]
        failureDict = allList[3]
        jsonDict = allList[4]
        try:
            a=0
            logger.debug("check_all_validate=====")
            #logger.debug("ApiName"+ApiName)
            for param, value in content.items():
                if dictVar==inputDict:
                    stripValue=value.strip()
                    content[param]=stripValue
                expectList.append(param)
            print content
            #logger.debug(expectList)
            for key, value in dictVar.items():
                if key == apiName:
                    for key1, value1 in value.items():
                        logger.debug(key1)
                        for value2 in value1:
                            fieldParam = value2.parameter
                            #logger.debug("Parameter="+b)
                            #logger.debug(dictVar.get(b))
                            optional= dictVar.get(apiName).get(fieldParam)[0].optional
                            #logger.debug("optional====="+optional) 
                            if (optional == utilClass.read_property('YES')):
                                #logger.debug("Yes="+b)
                                if (fieldParam in expectList):
                                    #logger.debug("In expect list")
                                    paramValue=content[fieldParam]
                                    #logger.debug(paramValue)
                                    if paramValue is not None:
                                        paramValue=paramValue.strip()
                                    if not paramValue:
                                        if paramValue is not None:
                                            arrayValue = [fieldParam]
                                            errorMsg = self.create_error_message (utilClass.read_property ("MANDATORY_FIELD"), arrayValue)
                                            if errorMsg:
                                                errorList.append (errorMsg)
                                else:
                                    arrayValue = [fieldParam]
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
                    dataType= dictVar.get(apiName).get(param)[0].dataType
                    logger.debug("param="+param)
                    logger.debug("dataType="+dataType)
                    validValues= dictVar.get(apiName).get(param)[0].validValues
                    #logger.debug("validValues="+validValues)
                    if not dictVar==failureDict and not dictVar==jsonDict:
                        errorList=self.data_type_validation(dataType,value,param,validValues,apiName,dictVar,content)
                        errorListAll.extend (errorList)
                        if not errorList:
                            #if utilClass.is_not_blank(str(value)):
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
            if not (dataType == utilClass.read_property('JSON')) and not (dataType == utilClass.read_property('JSONLIST')):
                if not (dataType == utilClass.read_property('LIST')):
                    logger.debug("==Inside valid values")
                    if utilClass.is_blank(str(validValues)):#and utilClass.is_blank(paramValue):
                        pass
                    else:
                        check=1
                        words = validValues.split (',')
                        for word in words:
                            if (str(paramValue)==word.strip()):
                                check = 0
                        if utilClass.is_not_blank(str(paramValue)) and check==0:
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
            if not (dataType == utilClass.read_property('JSON')) and not (dataType == utilClass.read_property('JSONLIST')) and not (dataType == utilClass.read_property('LIST')):
                if utilClass.is_blank(str(validValues)):
                    pass
                else:
                    check=1
                    words = validValues.split (',')
                    for word in words:
                        if (str(paramValue).__contains__(word.strip())):
                            check = 0
                    if utilClass.is_not_blank(str(paramValue)) and check==0:
                        pass
                    else:
                        arrayValue=[param,validValues,paramValue]
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
        warningDict={}
        warningResponse={}
        jsonWarningResponse={}
        finalResponse=[]
        warningList=[]
        missingList=[]
        transformResponse={}
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
                        results = self.validation_parameter (response, apiName, dictVar)
                        result=results[0]
                        response=results[1]
                        invalidDict=results[2]
                        if invalidDict:
                            warningDict.update(invalidDict)
                        if not result:
                            logger.debug("After manipulation_default")
                            response = self.manipulation_default (response, apiName, dictVar)
                            result = self.add_key_request (response, apiName, dictVar)
                        if not result:
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
                        results = self.validation_parameter (response, apiName, dictVar)
                        result=results[0]
                        response=results[1]
                        invalidDict=results[2]
                        if invalidDict:
                            warningList.append(invalidDict)
                        logger.debug(result)
                        if result and result[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                            missingList.append(result[utilClass.read_property('ERROR_MSG')])
                        if not result:
                            logger.debug("After validation_all in success")
                            logger.debug(response)
                            result = self.validation_all (response, apiName, dictVar)
                            if result and result[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                                missingList.append(result[utilClass.read_property('ERROR_MSG')])
                        logger.debug(result)
                        if not result:
                            logger.debug("After manipulation_transformation in success")
                            response = self.manipulation_transformation(response, apiName, dictVar)
                            if response and utilClass.read_property('STATUS') in response:
                                if response[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                                    missingList.append(response[utilClass.read_property('ERROR_MSG')])
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
                finalResponse.append(resultAll)
                if warningList:
                    warningResponse=self.create_warning_response(warningList,dictVar,jsonObject,"")
                    finalResponse.append(warningResponse)
                if missingList:   
                    missingResponse=self.create_missing_response(result,jsonObject,missingList,warningResponse,dictVar)
                    finalResponse=[]
                    finalResponse.append(missingResponse)
                return finalResponse       
            else:            # it is a dictionary
                stat = jsonObject.get(utilClass.read_property('STATUS'))
                stat=str(stat)
                if not dictVar==inputDict:
                    if stat == utilClass.read_property ('OK'):
                        dictVar=successDict
                    elif stat == utilClass.read_property ('NOT_OK'): #or stat == utilClass.read_property ('NONE'):
                        dictVar=failureDict
                    else:
                        dictVar=successDict
                if(dictVar==inputDict and inputValidation==utilClass.read_property("YES")):
                    logger.debug("Validation parameter")
                    results = self.validation_parameter (jsonObject, apiName, dictVar)
                    result=results[0]
                    jsonObject=results[1]
                    invalidDict=results[2]
                    if invalidDict:
                            warningDict.update(invalidDict)
                    if not result:
                        logger.debug("After manipulation_default")
                        jsonObject = self.manipulation_default (jsonObject, apiName, dictVar)
                        result = self.add_key_request (jsonObject, apiName, dictVar)
                    if not result: 
                        logger.debug("After validation_all")
                        result = self.validation_all (jsonObject, apiName, dictVar)
                    if not result:
                        logger.debug("After manipulation_transformation")
                        jsonObject = self.manipulation_transformation(jsonObject, apiName, dictVar)
                        result=jsonObject
                        logger.debug("result="+str(result))
                elif(dictVar==successDict and responseValidation==utilClass.read_property("YES")):
                    logger.debug("INSIDE SUCCESS")
                    results = self.validation_parameter (jsonObject, apiName, dictVar)
                    result=results[0]
                    jsonObject=results[1]
                    invalidDict=results[2]
                    if invalidDict:
                            warningDict.update(invalidDict)
                    if result and result[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                            missingList.append(result[utilClass.read_property('ERROR_MSG')])
                    logger.debug(result)
                    if not result:
                        logger.debug("After validation_all in success")
                        logger.debug(jsonObject)
                        result = self.validation_all (jsonObject, apiName, dictVar)
                        if result and result[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                            missingList.append(result[utilClass.read_property('ERROR_MSG')])
                        if utilClass.read_property("ERROR_MSG") in jsonObject or utilClass.read_property("WARNING_MESSAGE") in jsonObject:
                            #extract actual data from missing field and extra field
                            results=self.create_extracted_response(jsonObject,warningDict)
                            result=results[0]
                            jsonWarningResponse=results[1]
                            warningDict={}
                    logger.debug(result)
                    if not result:
                        logger.debug("After manipulation_transformation in success")
                        transformResponse=jsonObject
                        jsonObject = self.manipulation_transformation(jsonObject, apiName, dictVar)
                        result=jsonObject
                        if jsonObject and utilClass.read_property('STATUS') in jsonObject:
                            if jsonObject[utilClass.read_property('STATUS')]==utilClass.read_property('NOT_OK'):
                                missingList.append(jsonObject[utilClass.read_property('ERROR_MSG')])
                                jsonObject=transformResponse
                        logger.debug("result="+str(result))
                elif(dictVar==failureDict and responseValidation==utilClass.read_property("YES")):
                    result=jsonObject
                    result=self.add_list_msg(result)
                else:
                    result=jsonObject
                finalResponse.append(result)
                if warningDict:
                    warningResponse=self.create_warning_response(warningDict,dictVar,jsonObject,"")
                    finalResponse.append(warningResponse)
                if missingList:   
                    missingResponse=self.create_missing_response(result,jsonObject,missingList,warningResponse,dictVar)
                    finalResponse=[]
                    finalResponse.append(missingResponse)
                if jsonWarningResponse:
                    finalResponse.append(jsonWarningResponse)    
                return finalResponse       
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
                    if not dataType=='JSON' and not dataType=='JSONLIST' and not dataType=='LIST':
                        for listName,listValue in listDict.items():
                            expectList.append(listName)
                            for sourceValue,remainValue in listValue.items():
                                if listName==transformation:
                                    expectListValue.append(sourceValue)
                        print 'expectList',expectList
                        #listValue= dictVar.get(apiName).get(param)[0].transformation
                        if transformation:
                            if transformation in expectList:
                                if utilClass.is_not_blank(str(value)) and value in expectListValue:
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
                    jsonObject = self.error_response (errorList, utilClass.read_property("NOT_OK"))           
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return jsonObject
    
    
    '''This method used to create response for missing field'''
    def create_missing_response(self,result,jsonObject,missingList,warningResponse,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        resultAll=[]
        missingListAll=[]
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        try:
            if not dictVar==jsonDict:
                if type(jsonObject) is list :
                    result[utilClass.read_property('ERROR_MSG')]=missingList
                    result[utilClass.read_property('RESPONSE')]=jsonObject
                    if warningResponse:
                        warningMessage=warningResponse[utilClass.read_property("WARNING_MESSAGE")] 
                        result[utilClass.read_property('WARNING_MESSAGE')]=warningMessage
                    resultAll.append(result)
                    return resultAll
                else:
                    result[utilClass.read_property('ERROR_MSG')]=missingList[0]
                    result[utilClass.read_property('RESPONSE')]=jsonObject
                    if warningResponse:
                        warningMessage=warningResponse[utilClass.read_property("WARNING_MESSAGE")] 
                        result[utilClass.read_property('WARNING_MESSAGE')]=warningMessage
                    return result
            else:#Json Array
                if utilClass.read_property("ERROR_MSG") in jsonObject:
                    missingListAll=jsonObject[utilClass.read_property("ERROR_MSG")]
                    missingListAll.append(missingList)
                    jsonObject[utilClass.read_property("ERROR_MSG")]=missingListAll
                else:
                    missingListAll.append(missingList)
                    jsonObject[utilClass.read_property("ERROR_MSG")]=missingListAll
                print jsonObject
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
       
    
    
    '''This method used to create response for missing field'''
    def missing_field_response(self,result,jsonObject):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        missingList=[]
        try:
            errorList=result[utilClass.read_property('ERROR_MSG')]
            for missingList in errorList:
                if missingList.__contains__(utilClass.read_property('IS_MISSING_FIELD')):
                    result[utilClass.read_property('RESPONSE')]=jsonObject
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return result
    
    
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
            if utilClass.is_blank(str(transformation)):
                pass
            else:
                if utilClass.is_not_blank(str(paramValue)):
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
            if utilClass.is_blank(str(default)):
                pass
            elif(utilClass.is_blank(str(paramvalue))):
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
                result = self.error_response (errorList, utilClass.read_property("NOT_OK"))
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
        results = []
        try:
            if jsonObject:
                param = self.validate_length_and_invalid_field (jsonObject, apiName, dictVar)
                isErrorAvailable = param[0]
                errorList = param[1]
                invalidDict = param[2]
                if invalidDict:
                    jsonObject=self.remove_warning_list_parameter(jsonObject,invalidDict)
                if (isErrorAvailable == True):
                    result = self.error_response (errorList, utilClass.read_property("NOT_OK"))
                results.append(result)
                results.append(jsonObject)
                results.append(invalidDict)
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))        
        return results
    
    '''This method used to remove  key, value from success response.and add warning dictionary in to success response.'''
    def remove_warning_list_parameter(self,jsonObject,invalidDict):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        try:
            if type(jsonObject) is list:
                """for key,value in invalidDict.items():
                    if key==utilClass.read_property('WARNING_LIST'):
                        for value in value:
                            del jsonObject[value]
                jsonObject.append(invalidDict)"""
            else:
                for key,value in invalidDict.items():
                    del jsonObject[key]
                #jsonObject[utilClass.read_property('WARNING_LIST')]=invalidDict
                print jsonObject      
            
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))        
        return jsonObject
    
    
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
                    result = self.error_response (errorList, utilClass.read_property("NOT_OK"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return  result
    
    
    '''This method used to check  all key is in input request.
    if error in list,it will call error response method'''
    def add_key_request(self,jsonObject,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        result = {}
        try:
            if jsonObject:
                addKey = self.add_key_request_validate(jsonObject, apiName, dictVar)
                isErrorAvailable = addKey[0]
                errorList = addKey[1]
                if (isErrorAvailable == True):
                    result = self.error_response (errorList, utilClass.read_property("NOT_OK"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return  result
    
    
    '''This method used to validate  all key is in input request.
    if error in list,it will call error response method'''
    def add_key_request_validate(self,jsonObject,apiName,dictVar):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        errorList=[]
        expectList=[]
        isErrorAvailale=False
        try:
            print 'Previous Input ',jsonObject
            for param, value in jsonObject.items():
                expectList.append(param)
            for key, value in dictVar.items():
                if key == apiName:
                    for key1, value1 in value.items():
                        logger.debug(key1)
                        for value2 in value1:
                            fieldParam = value2.parameter
                            optional= dictVar.get(apiName).get(fieldParam)[0].optional
                            default= dictVar.get(apiName).get(fieldParam)[0].default 
                            if (fieldParam not in expectList):
                                if default and optional == utilClass.read_property('YES'):
                                    jsonObject[fieldParam]=default
                                elif optional == utilClass.read_property('YES'):
                                    arrayValue = [fieldParam]
                                    errorMsg = self.create_error_message (utilClass.read_property ("MANDATORY_FIELD"), arrayValue)
                                    errorList.append(errorMsg)
                                elif optional != utilClass.read_property('YES'): 
                                    jsonObject[fieldParam]=''
            print 'After Change Input ',jsonObject              
            if errorList:
                isErrorAvailale = True
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return isErrorAvailale,errorList
    
    
    '''This method is used to create error response from error list'''
    def error_response(self,errorList,stat):
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
    
    '''This method is used to create warning response from warning list'''
    def warning_response(self,warningList,stat):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        response_data = {}
        try:
            for warning in warningList:
                response_data.setdefault(utilClass.read_property("WARNING_MESSAGE"), [])
                response_data[utilClass.read_property("WARNING_MESSAGE")].append(warning)
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
            if errorMessage:
                for index, item in enumerate (arrayValue):
                    index = str(index)
                    if type(item)==int:
                        item = str (item)
                    errorMessage = errorMessage.replace ('['+index+']',item)
            else:
                errorMessage="No Error Message in Property File"
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return  errorMessage
    
    
    '''This method is used to create error response'''
    def create_error_response(self,exception):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        response_data=[]
        response_error=''
        try:    
            stat = utilClass.read_property ("NOT_OK")
            errorList = []
            errorMsg = exception
            errorList.append(errorMsg)
            response_error=self.error_response(errorList,stat)
            response_data.append(response_error)
        except Exception as exception:
            print "Exception",exception
            raise exception       
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return response_data
    
    '''This method is used to create warning response'''
    def create_warning_response(self,warningDict,dictVar,content,validValues):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        response_data={}
        warningList = []
        warningListAll = []
        returnAllDict = ReturnAllDict()
        allList = returnAllDict.return_dict()
        jsonDict = allList[4]
        try: 
            stat = utilClass.read_property ("WARNING")
            if not dictVar==jsonDict:
                if type(warningDict) is list:  
                    response_data[utilClass.read_property("STATUS")]=stat
                    for warningDict in warningDict:#list
                        warningList = []
                        for param,paramValue in warningDict.items():
                            warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")       
                            warningList.append(warningMsg)
                        warningListAll.append(warningList)
                    response_data[utilClass.read_property("WARNING_MESSAGE")]=warningListAll
                    return response_data
                else:    
                    for param,paramValue in warningDict.items():
                        warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")       
                        warningList.append(warningMsg)
                    response_data=self.warning_response(warningList, stat)#dict
                    return response_data
            else:     #Json Array 
                if utilClass.read_property("WARNING_MESSAGE") in content:
                    warningListAll=content[utilClass.read_property("WARNING_MESSAGE")]
                    for param,paramValue in warningDict.items():
                        #warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")+" in "+validValues+" Json Array Sheet"       
                        arrayValue = [str(param),str(paramValue),validValues]
                        warningMsg = self.create_error_message (utilClass.read_property ("EXTRA_FIELD_JSON_ARRAY_MSG"), arrayValue)
                        warningList.append(warningMsg)#dict
                    warningListAll.append(warningList)
                    content[utilClass.read_property("WARNING_MESSAGE")]=warningListAll
                else:
                    for param,paramValue in warningDict.items():
                        #warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")+" in "+validValues+" Json Array Sheet"        
                        arrayValue = [str(param),str(paramValue),validValues]
                        warningMsg = self.create_error_message (utilClass.read_property ("EXTRA_FIELD_JSON_ARRAY_MSG"), arrayValue)
                        warningList.append(warningMsg)#dict
                    warningListAll.append(warningList)
                    content[utilClass.read_property("WARNING_MESSAGE")]=warningListAll
                print content
        except Exception as exception:
            print "Exception",exception
            raise exception        
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        
    
    '''This method is used to create extracted warning response and error response'''
    def create_extracted_response(self,content,warningDict):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        responseData={}
        warningResponse={}
        warningListAll = []
        warningList=[]
        errorListAll = []
        try:     
            #Json Array 
            jsonObject=content
            if utilClass.read_property("ERROR_MSG") in content and utilClass.read_property("WARNING_MESSAGE") in content:
                errorListAll=content[utilClass.read_property("ERROR_MSG")]
                warningListAll=content[utilClass.read_property("WARNING_MESSAGE")]
                del content[utilClass.read_property("ERROR_MSG")]
                del content[utilClass.read_property("WARNING_MESSAGE")]
                responseData[utilClass.read_property('RESPONSE')]=content
                responseData[utilClass.read_property("STATUS")]=utilClass.read_property("NOT_OK")
                responseData[utilClass.read_property("ERROR_MSG")]=errorListAll
                if warningDict:#from success sheet warning append
                    for param,paramValue in warningDict.items():
                        warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")       
                        warningList.append(warningMsg)#dict
                    if warningList:
                        warningListAll.append(warningList)
                responseData[utilClass.read_property("WARNING_MESSAGE")]=warningListAll
                
            elif utilClass.read_property("ERROR_MSG") in content:
                errorListAll=content[utilClass.read_property("ERROR_MSG")]
                del content[utilClass.read_property("ERROR_MSG")]
                responseData[utilClass.read_property('RESPONSE')]=content
                responseData[utilClass.read_property("STATUS")]=utilClass.read_property("NOT_OK")
                responseData[utilClass.read_property("ERROR_MSG")]=errorListAll
                
                
            elif utilClass.read_property("WARNING_MESSAGE") in content:
                warningListAll=content[utilClass.read_property("WARNING_MESSAGE")]
                del content[utilClass.read_property("WARNING_MESSAGE")]
                responseData=content
                warningResponse[utilClass.read_property("STATUS")]=utilClass.read_property("WARNING")
                if warningDict:#from success sheet warning append
                    for param,paramValue in warningDict.items():
                        warningMsg=str(param)+":"+str(paramValue)+" "+utilClass.read_property("EXTRA_FIELD_MSG")       
                        warningList.append(warningMsg)#dict
                    if warningList:
                        warningListAll.append(warningList)
                warningResponse[utilClass.read_property("WARNING_MESSAGE")]=warningListAll
            
            return responseData,warningResponse
        
        except Exception as exception:
            print "Exception",exception
            raise exception        
        logger.info(utilClass.read_property("EXITING_METHOD"))
    
    
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
    
    
    '''This method is used to get source Url from System Sheet.the source Url and Request Url is mismatched the error is shown'''
    def get_source_url(self,requestUrl,systemDict):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        sourceUrl=''
        try:
            logger.debug(systemDict)
            logger.debug(requestUrl)        
            sourceUrl=systemDict.get(requestUrl)[0].sourceUrl
        except Exception:
            raise ValueError(utilClass.read_property("INVALID_SOURCE_URL"))     
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return sourceUrl
    
   
    '''This method is used to get target Url path from Api Sheet.'''
    def get_target_url_path(self,apiHomeDict,apiName):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        urlPath=''
        try:    
            urlPath = apiHomeDict.get(apiName)[0].url
        except Exception:
            raise ValueError(utilClass.read_property("INVALID_URL"))  
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return urlPath
    
    
    '''This method is used to validate record and field separator.'''
    def record_and_field_separator(self,systemDict,sourceUrl):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
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
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        
        
    '''This method is used to validate content type is application/json or not.'''
    def content_type(self,contentType):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
            if contentType:
                if contentType==utilClass.read_property("CONTENT_TYPE"):
                    pass
                else:
                    raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
            else:
                raise ValueError(utilClass.read_property("INVALID_CONTENT_TYPE"))
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        
    
    '''This method is used to get tso response status.'''
    def get_target_response_status(self,request):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
            if type(request) is list:
                for dict_var in request:
                    stat=dict_var.get(utilClass.read_property('STATUS'))
                    if stat == utilClass.read_property ('OK'):
                        targetResponseStatus = utilClass.read_property('SUCCESS')
                        pass
                    else:
                        targetResponseStatus = utilClass.read_property('FAILURE')
                        break
            else:
                stat = request.get(utilClass.read_property('STATUS'))
                stat=str(stat)
                if stat == utilClass.read_property ('OK'):
                    targetResponseStatus = utilClass.read_property('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    targetResponseStatus = utilClass.read_property('FAILURE')
                else:
                    targetResponseStatus=utilClass.read_property('SUCCESS')
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return targetResponseStatus
    
    
    
    '''This method is used to get api response status.'''
    def get_source_transmit_status(self,request):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
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
            else:          
                stat= request.get (utilClass.read_property('STATUS'))
                stat=str(stat)
                if stat== utilClass.read_property ('OK'):
                    sourceTransmitStatus=utilClass.read_property ('SUCCESS')
                elif stat == utilClass.read_property ('NOT_OK'):
                    sourceTransmitStatus = utilClass.read_property ('FAILURE')
                else:
                    sourceTransmitStatus = utilClass.read_property ('SUCCESS')
        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))  
        return sourceTransmitStatus
    
    
    '''This method is used to get Session Expired response for valid_answer api.'''
    def get_session_expired_response(self,output):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
            encriptResponse=output[utilClass.read_property("JENCRESP")]
            if encriptResponse==utilClass.read_property("SE"):
                raise ValueError(utilClass.read_property("SESSION_EXPIRED"))  
            else:
                pass
        except Exception:
            raise ValueError(utilClass.read_property("SESSION_EXPIRED"))    
        logger.info(utilClass.read_property("EXITING_METHOD"))   
        
        
    '''This method is used to get Session Expired response for valid_answer api.'''
    def invalid_data_account_info(self,output,apiName):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))  
        try:    
            if apiName==utilClass.read_property("account_info"):
                if output.get(utilClass.read_property('ERROR_MSG_SMALL'))=='':
                    output[utilClass.read_property('STATUS')]=utilClass.read_property ("NOT_OK")
                    output[utilClass.read_property('ERROR_MSG')]=utilClass.read_property("INVALID_VALUE_ACCOUNT_INFO")  
                    del output[utilClass.read_property('ERROR_MSG_SMALL')]
            else:
                pass
        except Exception as exception:
            raise exception    
        logger.info(utilClass.read_property("EXITING_METHOD"))   
        return output