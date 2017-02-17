'''This class is used to initialize api excel sheet'''
class ApiClass(object):

    '''This method is used to initialize api excel sheet'''
    def __init__(self, hashApi, source,subject,ch,apiName,description,sourceUrl,url,logging,inputApi,inputEncryption,resonseEncryption,notes,inputSample,inputValidation,responseValidation):
        self.hashApi = hashApi
        self.source = source
        self.subject = subject
        self.ch = ch
        self.apiName = apiName
        self.description = description
        self.sourceUrl = sourceUrl
        self.url = url
        self.logging = logging
        self.inputApi = inputApi
        self.inputEncryption = inputEncryption
        self.resonseEncryption = resonseEncryption
        self.notes = notes
        self.inputSample = inputSample
        self.inputValidation = inputValidation
        self.responseValidation = responseValidation


'''This class is used to initialize input excel sheet'''
class InputClass(object):

    '''This method is used to initialize input excel sheet'''
    def __init__(self, inputColHash, apiName,sno,parameter,description,businessTag,dataType,validValues,optional,default,transformation,investakScreenFieldSample):
        self.inputColHash = inputColHash
        self.apiName = apiName
        self.sno = sno
        self.parameter = parameter
        self.description = description
        self.businessTag = businessTag
        self.dataType = dataType
        self.validValues = validValues
        self.optional = optional
        self.default = default
        self.transformation = transformation
        self.investakScreenFieldSample = investakScreenFieldSample


'''This class is used to initialize success excel sheet'''
class SuccessClass(object):
    
    '''This method is used to initialize success excel sheet'''
    def __init__(self, successColHash, apiName,sno,parameter,description,businessTag,dataType,validValues,optional,transformation,specialProcess):
        self.successColHash = successColHash
        self.apiName = apiName
        self.sno = sno
        self.parameter = parameter
        self.description = description
        self.businessTag = businessTag
        self.dataType = dataType
        self.validValues = validValues
        self.optional = optional
        self.transformation = transformation
        self.specialProcess = specialProcess


'''This class is used to initialize failure excel sheet'''
class FailureClass(object):

    '''This method is used to initialize failure excel sheet'''
    def __init__(self, failureColHash, apiName,sno,parameter,description,dataType,validValues):
        self.failureColHash = failureColHash
        self.apiName = apiName
        self.sno = sno
        self.parameter = parameter
        self.description = description
        self.dataType = dataType
        self.validValues = validValues


'''This class is used to initialize jsonArray excel sheet'''
class JsonArrayClass(object):
    
    '''This method is used to initialize jsonArray excel sheet'''
    def __init__(self,jsonColHash,arrayName,sno,parameter,description,dataType,validValues):
        self.jsonColHash = jsonColHash
        self.arrayName = arrayName
        self.sno = sno
        self.parameter = parameter
        self.description = description
        self.dataType = dataType
        self.validValues = validValues
        
        
'''This class is used to initialize list excel sheet'''
class ListClass(object):

    '''This method is used to initialize list excel sheet'''
    def __init__(self,listColHash,listName,listNo,sourceValue,targetValue,dataType):
        self.listColHash = listColHash
        self.listName = listName
        self.listNo = listNo
        self.sourceValue = sourceValue
        self.targetValue = targetValue
        self.dataType = dataType