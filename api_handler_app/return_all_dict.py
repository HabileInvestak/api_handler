from api_handler_app.excel_sheet import *
from properties.p import Property

listOfDict=[]

'''This class is used for initially read all excel sheet or update all excel sheet with property file to return as a list.
we will use this list which contains all excel sheets for validation when apiName is call'''
class ReturnAllDict():
    
    '''This is used to update all excel sheet with property file to store as a list
    we will use this list which contains all excel sheets for validation when apiName is call'''
    def update_excel_property(self):
        prop=Property()
        propObj = prop.load_property_files('E:\\Investak\\investak_local.properties')
        a = ExcelSheetApi()
        i = ExcelSheetInput()
        s = ExcelSheetSuccess()
        f = ExcelSheetFailure()
        j = ExcelSheetJson()
        l = ExcelSheetLists()
        sys = ExcelSheetSystem()
        apiHomeDict = a.api_home_dict(propObj)
        inputDict = i.input_dict(propObj)
        successDict = s.success_dict(propObj)
        failureDict = f.failure_dict(propObj)
        jsonDict = j.json_dict(propObj)
        listDict = l.list_dict(propObj) 
        systemDict = sys.system_dict(propObj) 
        listOfDictTemp=[apiHomeDict,inputDict,successDict,failureDict,jsonDict,listDict,propObj,systemDict]
        global listOfDict
        listOfDict=listOfDictTemp
        print "call Loading dictioanry from excel once deployment"
        return listOfDict
    
    '''This method is used to return read all excel sheet with property file as a list
    we will use this list which contains all excel sheets for validation when apiName is call'''
    def return_dict(self):
        return listOfDict