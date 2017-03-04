import logging
from xlrd import open_workbook
from api_handler_app.excel_read_class import *

logger = logging.getLogger('api_handler_app.excel_sheet.py')

'''This class is used to read api excel sheet
and stored as a api dictionary with apiName is key and remaining column is value'''
class ExcelSheetApi():

    '''This method is used to read api excel sheet.
    and stored as a api dictionary with apiName is key and remaining column is value'''
    def api_home_dict(self,propObj):  
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        sheet = wb.sheet_by_index(2)
        rows=sheet.nrows
        #colmns=sheet.ncols
        apiHomeDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                hashApi = str(sheet.cell(rownum, 0).value).strip()
                source = str(sheet.cell(rownum, 1).value).strip()
                subject = str(sheet.cell(rownum, 2).value).strip()
                ch = str(sheet.cell(rownum, 3).value).strip()
                apiName = str(sheet.cell(rownum, 4).value).strip()
                description = str(sheet.cell(rownum, 5).value).strip()
                sourceUrl = str(sheet.cell(rownum, 6).value).strip().strip()
                url = str(sheet.cell(rownum, 7).value).strip().strip()
                logging = str(sheet.cell(rownum, 8).value).strip().strip()
                inputApi = str(sheet.cell(rownum, 9).value).strip()
                inputEncryption = str(sheet.cell(rownum, 10).value).strip()
                resonseDecryption = str(sheet.cell(rownum, 11).value).strip()
                notes = (sheet.cell(rownum, 12).value).encode('utf-8').strip()
                inputSample = str(sheet.cell(rownum, 13).value).strip()
                inputValidation = str(sheet.cell(rownum, 14).value).strip()
                responseValidation = str(sheet.cell(rownum, 15).value).strip()
                a=ApiClass(hashApi,source,subject,ch,apiName,description,sourceUrl,url,logging,inputApi,inputEncryption,resonseDecryption,notes,inputSample,inputValidation,responseValidation)
    
                apiHomeDict[apiName] = [a]

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return apiHomeDict


#INPUT
'''This class is used to read input excel sheet
and stored as a input dictionary with apiName is key and within apiName parameter is key remaining column is value'''
class ExcelSheetInput():
    
    '''This method is used to read input excel sheet
    and stored as a input dictionary with apiName is key and within apiName parameter is key remaining column is value'''
    def input_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        sheet = wb.sheet_by_index(4)
        rows=sheet.nrows
        #colmns=sheet.ncols

        inputParamDict = {}
        inputDict={}
        tempParamDict={}
        try:
            for rownum in range(rows):
    
                if rownum==0:
                    continue
                inputColHash= str(sheet.cell(rownum,0).value).strip()
                apiName= str(sheet.cell(rownum,1).value).strip()
                sno =  sheet.cell(rownum, 2).value
                if isinstance(sno, float) and sno.is_integer():
                    sno = int(sno)
                    sno = str(sno).strip()
                else:
                    sno = str(sno).strip()
                parameter = str(sheet.cell(rownum, 3).value).strip()
                description =(sheet.cell(rownum, 4).value).encode('utf-8').strip()
                businessTag =  str(sheet.cell(rownum, 5).value).strip()
                dataType = str(sheet.cell(rownum, 6).value).strip()
                validValues = sheet.cell(rownum, 7).value
                if dataType!='Decimal' and isinstance(validValues, float) and validValues.is_integer():
                    validValues = int(validValues)
                    validValues = str(validValues).strip()
                else:
                    validValues = str(validValues).strip()
                optional = str(sheet.cell(rownum, 8).value).strip()
                default = sheet.cell(rownum, 9).value
                if dataType!='Decimal' and isinstance(default, float) and default.is_integer():
                    default = int(default)
                    default = str(default).strip()
                else:
                    default = str(default).strip()
                transformation = sheet.cell(rownum, 10).value
                if dataType!='Decimal' and isinstance(transformation, float) and transformation.is_integer():
                    transformation = int(transformation)
                    transformation = str(transformation).strip()
                else:
                    transformation = str(transformation).strip()
                investakScreenFieldSample = str(sheet.cell(rownum, 11).value).strip()
                if apiName not in inputDict:
                    inputDict[apiName] = {}
    
                i=InputClass(inputColHash,apiName,sno,parameter,description,businessTag,dataType,validValues,optional,default,transformation,investakScreenFieldSample)
                inputParamDict[parameter] = [i]
                for k, v in inputDict.items():
                    if k.__contains__(apiName):
                        tempParamDict[parameter] =  inputParamDict[parameter]
                        inputDict[apiName].update({ parameter : tempParamDict[parameter]})

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return inputDict


#SUCCESS
'''This class is used to read success excel sheet
and stored as a success dictionary with apiName is key and within apiName parameter is key remaining column is value'''
class ExcelSheetSuccess():
    
    '''This method is used to read success excel sheet
    and stored as a success dictionary with apiName is key and within apiName parameter is key remaining column is value'''
    def success_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        tempParamDict={}
        sheet = wb.sheet_by_index(5)
        rows=sheet.nrows
        #colmns=sheet.ncols
        successParamDict = {}
        successDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                successColHash= str(sheet.cell(rownum,0).value).strip()
                apiName= str(sheet.cell(rownum,1).value).strip()
                sno =  sheet.cell(rownum, 2).value
                if isinstance(sno, float) and sno.is_integer():
                    sno = int(sno)
                    sno = str(sno).strip()
                else:
                    sno = str(sno).strip()
                parameter = str(sheet.cell(rownum, 3).value).strip()
                description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                businessTag =  str(sheet.cell(rownum, 5).value).strip()
                dataType = str(sheet.cell(rownum, 6).value).strip()
                validValues =  sheet.cell(rownum, 7).value
                if dataType!='Decimal' and isinstance(validValues, float) and validValues.is_integer():
                    validValues = int(validValues)
                    validValues = str(validValues).strip()
                else:
                    validValues = str(validValues).strip()
                optional =  str(sheet.cell(rownum, 8).value).strip()
                transformation =  sheet.cell(rownum, 9).value
                if dataType!='Decimal' and isinstance(transformation, float) and transformation.is_integer():
                    transformation = int(transformation)
                    transformation = str(transformation).strip()
                else:
                    transformation = str(transformation).strip()
                specialProcess = str(sheet.cell(rownum, 10).value).strip()
                if apiName not in successDict:
                    successDict[apiName] = {}
                s=SuccessClass(successColHash,apiName,sno,parameter,description,businessTag,dataType,validValues,optional,transformation,specialProcess)
                successParamDict[parameter] = [s]
                for k, v in successDict.items():
                    if k.__contains__(apiName):
                        tempParamDict[parameter] =  successParamDict[parameter]
                        successDict[apiName].update({ parameter : tempParamDict[parameter]})
        
        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return successDict


#FAILURE
'''This class is used to read failure excel sheet
and stored as a failure dictionary with apiName is key and within apiName parameter is key remaining column is value'''
class ExcelSheetFailure():

    '''This method is used to read failure excel sheet dictionary
    and stored as a failure dictionary with apiName is key and within apiName parameter is key remaining column is value'''
    def failure_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        tempParamDict={}
        sheet = wb.sheet_by_index(6)
        rows=sheet.nrows
        #colmns=sheet.ncols

        failureParamDict = {}
        failureDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                failureColHash= str(sheet.cell(rownum,0).value).strip()
                apiName= str(sheet.cell(rownum,1).value).strip()
                sno =sheet.cell(rownum, 2).value
                if isinstance(sno, float) and sno.is_integer():
                    sno = int(sno)
                    sno = str(sno).strip()
                else:
                    sno = str(sno).strip()
                parameter =  str(sheet.cell(rownum, 3).value).strip()
                description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                dataType =  str(sheet.cell(rownum, 5).value).strip()
                validValues = sheet.cell(rownum, 6).value
                if dataType!='Decimal' and isinstance(validValues, float) and validValues.is_integer():
                    validValues = int(validValues)
                    validValues = str(validValues).strip()
                else:
                    validValues = str(validValues).strip()
                
                if apiName not in failureDict:
                    failureDict[apiName] = {}
                f = FailureClass(failureColHash, apiName, sno, parameter, description,dataType, validValues)
                failureParamDict[parameter] = [f]
                for k, v in failureDict.items():
                    if k.__contains__(apiName):
                        tempParamDict[parameter] =  failureParamDict[parameter]
                        failureDict[apiName].update({ parameter : tempParamDict[parameter]})

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return failureDict


#JSON ARRAY
'''This class is used to read jsonArray excel sheet
and stored as a jsonArray dictionary with arrayName is key and within arrayName parameter is key remaining column is value'''
class ExcelSheetJson():

    '''This method is used to read jsonArray excel sheet
    and stored as a jsonArray dictionary with arrayName is key and within arrayName parameter is key remaining column is value'''
    def json_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        tempParamDict={}
        sheet = wb.sheet_by_index(7)
        rows=sheet.nrows
        #colmns=sheet.ncols
        jsonArrayDict = {}
        jsonDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                jsonColHash= str(sheet.cell(rownum,0).value).strip()
                arrayName= str(sheet.cell(rownum,1).value).strip()
                sno =  sheet.cell(rownum, 2).value
                if isinstance(sno, float) and sno.is_integer():
                    sno = int(sno)
                    sno = str(sno).strip()
                else:
                    sno = str(sno).strip()
                parameter =  str(sheet.cell(rownum, 3).value).strip()
                description =  (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                dataType =  str(sheet.cell(rownum, 5).value).strip()
                validValues =  sheet.cell(rownum, 6).value
                if dataType!='Decimal' and isinstance(validValues, float) and validValues.is_integer():
                    validValues = int(validValues)
                    validValues = str(validValues).strip()
                else:
                    validValues = str(validValues).strip()
                
                if arrayName not in jsonDict:
                    jsonDict[arrayName] = {}
                j=JsonArrayClass(jsonColHash,arrayName,sno,parameter,description,dataType,validValues)
    
                jsonArrayDict[parameter] = [j]
                for k, v in jsonDict.items():
                    if k.__contains__(arrayName):
                        tempParamDict[parameter] = jsonArrayDict[parameter]
                        jsonDict[arrayName].update({parameter: tempParamDict[parameter]})

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return jsonDict
#print jsonArrayDict


#LISTS
'''This class is used to read list excel sheet
and stored as a list dictionary with listName is key and within listName sourceValue is key remaining column is value'''
class ExcelSheetLists():

    '''This method is used to read list excel sheet
    and stored as a list dictionary with listName is key and within listName sourceValue is key remaining column is value'''
    def list_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        tempParamDict={}
        sheet = wb.sheet_by_index(8)
        rows=sheet.nrows
        #colmns=sheet.ncols
        listDict = {}
        listSourceDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                listColHash= str(sheet.cell(rownum,0).value).strip()
                listName= str(sheet.cell(rownum,1).value).strip()
                listNo =  sheet.cell(rownum, 2).value
                if isinstance(listNo, float) and listNo.is_integer():
                    listNo = int(listNo)
                    listNo = str(listNo).strip()
                else:
                    listNo = str(listNo).strip()
                sourceValue =  sheet.cell(rownum, 3).value
                if isinstance(sourceValue, float) and sourceValue.is_integer():
                    sourceValue = int(sourceValue)
                    sourceValue = str(sourceValue).strip()
                else:
                    sourceValue = (sourceValue)
                targetValue =  sheet.cell(rownum, 4).value
                if isinstance(targetValue, float) and targetValue.is_integer():
                    targetValue = int(targetValue)
                    targetValue = str(targetValue).strip()
                else:
                    targetValue = str(targetValue).strip()
                dataType =  str(sheet.cell(rownum, 5).value).strip()
                if listName not in listDict:
                    listDict[listName] = {}
                l=ListClass(listColHash,listName,listNo,sourceValue,targetValue,dataType)
    
                listSourceDict[sourceValue] = [l]
                for k, v in listDict.items():
                    if k.__contains__(listName):
                        tempParamDict[sourceValue] = listSourceDict[sourceValue]
                        listDict[listName].update({sourceValue: tempParamDict[sourceValue]})

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return listDict
    
    
#SYSTEM
'''This class is used to read system excel sheet
and stored as a list dictionary with listName is key and within listName sourceValue is key remaining column is value'''
class ExcelSheetSystem():

    '''This method is used to read list excel sheet
    and stored as a list dictionary with listName is key and within listName sourceValue is key remaining column is value'''
    def system_dict(self,propObj):
        logger.info(propObj.get("ENTERING_METHOD"))
        wb = open_workbook (propObj.get("API_DICTIONARY_EXCEL"))
        sheet = wb.sheet_by_index(1)
        rows=sheet.nrows
        #colmns=sheet.ncols
        systemDict = {}
        try:
            for rownum in range(rows):
                if rownum==0:
                    continue
                systemColHash=str(sheet.cell(rownum,0).value).strip()
                systemName= str(sheet.cell(rownum,1).value).strip()
                systemType= str(sheet.cell(rownum,2).value).strip()
                dataContainerType =  str(sheet.cell(rownum, 3).value).strip()
                targetDeliveryLocation =  str(sheet.cell(rownum, 4).value).strip()
                encryptionMethod =  str(sheet.cell(rownum, 5).value).strip()
                loggingRequired =  str(sheet.cell(rownum, 6).value).strip()
                recordSeperator =  str(sheet.cell(rownum, 7).value).strip()
                fieldSeperator =  str(sheet.cell(rownum, 8).value).strip()
                notes =  str(sheet.cell(rownum, 9).value).encode('utf-8').strip()
                sourceUrl =  str(sheet.cell(rownum, 10).value).strip()
                targetUrl =  str(sheet.cell(rownum, 11).value).strip()
                
                sys=SystemClass(systemColHash,systemName,systemType,dataContainerType,targetDeliveryLocation,encryptionMethod,loggingRequired,recordSeperator,fieldSeperator,notes,sourceUrl,targetUrl)
                
                systemDict[sourceUrl] = [sys]
                

        except Exception as exception:
            raise exception
        logger.info(propObj.get("EXITING_METHOD"))
        return systemDict