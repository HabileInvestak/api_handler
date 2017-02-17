import logging
from xlrd import open_workbook
from utils import UtilClass 
from api_handler_app.excel_read_class import *

logger = logging.getLogger('api_handler_app.excel_sheet.py')

'''This class is used to read api excel sheet'''
class ExcelSheetApi():

    '''This method is used to read api excel sheet'''
    def api_home_dict(self):  
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                resonseEncryption = str(sheet.cell(rownum, 11).value).strip()
                notes = (sheet.cell(rownum, 12).value).encode('utf-8').strip()
                inputSample = str(sheet.cell(rownum, 13).value).strip()
                inputValidation = str(sheet.cell(rownum, 14).value).strip()
                responseValidation = str(sheet.cell(rownum, 15).value).strip()
                a=ApiClass(hashApi,source,subject,ch,apiName,description,sourceUrl,url,logging,inputApi,inputEncryption,resonseEncryption,notes,inputSample,inputValidation,responseValidation)
    
                apiHomeDict[apiName] = [a]

        except Exception as exception:
            raise exception
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return apiHomeDict


#INPUT
'''This class is used to read input excel sheet'''
class ExcelSheetInput():
    
    '''This method is used to read input excel sheet'''
    def input_dict(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                sno =  str(sheet.cell(rownum, 2).value).strip()
                parameter = str(sheet.cell(rownum, 3).value).strip()
                description =(sheet.cell(rownum, 4).value).encode('utf-8').strip()
                businessTag =  str(sheet.cell(rownum, 5).value).strip()
                dataType = str(sheet.cell(rownum, 6).value).strip()
                validValues = str(sheet.cell(rownum, 7).value).strip()
                optional = str(sheet.cell(rownum, 8).value).strip()
                default = str(sheet.cell(rownum, 9).value).strip()
                transformation = str(sheet.cell(rownum, 10).value).strip()
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
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return inputDict


#SUCCESS
'''This class is used to read success excel sheet'''
class ExcelSheetSuccess():
    
    '''This method is used to read success excel sheet'''
    def success_dict(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                sno =  str(sheet.cell(rownum, 2).value).strip()
                parameter = str(sheet.cell(rownum, 3).value).strip()
                description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                businessTag =  str(sheet.cell(rownum, 5).value).strip()
                dataType = str(sheet.cell(rownum, 6).value).strip()
                validValues =  str(sheet.cell(rownum, 7).value).strip()
                optional =  str(sheet.cell(rownum, 8).value).strip()
                transformation =  str(sheet.cell(rownum, 9).value).strip()
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
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return successDict


#FAILURE
'''This class is used to read failure excel sheet'''
class ExcelSheetFailure():

    '''This method is used to read failure excel sheet dictionary'''
    def failure_dict(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                sno =str(sheet.cell(rownum, 2).value).strip()
                parameter =  str(sheet.cell(rownum, 3).value).strip()
                description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                dataType =  str(sheet.cell(rownum, 5).value).strip()
                validValues =  str(sheet.cell(rownum, 6).value).strip()
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
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return failureDict


#JSON ARRAY
'''This class is used to read jsonArray excel sheet'''
class ExcelSheetJson():

    '''This method is used to read jsonArray excel sheet'''
    def json_dict(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                sno =  str(sheet.cell(rownum, 2).value).strip()
                parameter =  str(sheet.cell(rownum, 3).value).strip()
                description =  (sheet.cell(rownum, 4).value).encode('utf-8').strip()
                dataType =  str(sheet.cell(rownum, 5).value).strip()
                validValues =  str(sheet.cell(rownum, 6).value).strip()
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
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return jsonDict
#print jsonArrayDict


#LISTS
'''This class is used to read list excel sheet'''
class ExcelSheetLists():

    '''This method is used to read list excel sheet'''
    def list_dict(self):
        utilClass=UtilClass()
        logger.info(utilClass.read_property("ENTERING_METHOD"))
        wb = open_workbook (utilClass.read_property("API_DICTIONARY_EXCEL"))
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
                listNo =  str(sheet.cell(rownum, 2).value).strip()
                sourceValue =  str(sheet.cell(rownum, 3).value).strip()
                targetValue =  str(sheet.cell(rownum, 4).value).strip()
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
        logger.info(utilClass.read_property("EXITING_METHOD"))
        return listDict