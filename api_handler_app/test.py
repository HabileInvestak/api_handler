import json





contentList=['1','2','1']
content={}
try:
    for list in contentList:
        if contentList.count(list) > 1:
            print "dublicate key is ",list
            contentList.remove(list)
except Exception as e:
    print "exception is ",e 







paramValue=-2
p=str(paramValue)
print p
if paramValue:
    print 'paramValue',paramValue
    if(str(abs(paramValue)).isdigit()):
        pass
    else:
        print 'error'

paramValue=1351.15
paramValue = str(paramValue).replace(',', '')
paramValue = str(paramValue).replace(" ", "")
if paramValue=='00.00':
    paramValue='0.00'
print 'paramValue',paramValue
try:
    if paramValue and str(paramValue)!="NA":
        splitNum=str(paramValue).split('.', 1)
        if(str(paramValue).isdigit()):
            pass
        elif (isinstance (json.loads (str(paramValue)), (float)) and str(splitNum[1]).isdigit() and str(abs(int(splitNum[0]))).isdigit ()):#-ve value replace to +ve value
            pass
        else:
            print 'error'
except Exception as e:
    print "exception is ",e    



x = [1,2,3]
y = [4,5,6]
x.append(y)
print x

msg={}
list=[]
list.append('1')
list.append('2')
msg['w']=list
v=msg['w']
v.append('3')
msg['w']=v
v1='hi2'

if 'w' in msg:
    pass


"""from properties.p import Property
from datetime import datetime
import json
from django.http import JsonResponse
from api_handler_app.excel_read_class import *
from properties.p import Property

from xlrd import open_workbook

from xlrd import *
import win32com.client
import csv
import sys



warningDict={
    u"Status": u"cancelled",
    u"stat": u"Ok"
    }

warningList = []
for k,v in warningDict.items():
    warningMsg=k+":"+v+" "+"is an extra field"        
    warningList.append(warningMsg)
print warningList









try:
    xlApp = win32com.client.Dispatch("Excel.Application")
    print "Excel library version:", xlApp.Version
    filename,password = r"E:\\Investak\\Habile_Investak_API_Dictionary_Local.xlsx", '12345'
    xlwb = xlApp.Workbooks.Open(filename, False, True, None,Password=password)
    for sheet in xlwb.Worksheets:
        print sheet
    sheet = xlwb.Worksheets("API")
    rows=sheet.nrows
except Exception as e:
    print e


output={
    u"Status": u"cancelled",
    u"stat": u"Ok",
    u"Nstordno": u"170309000000064",
    u"Exchange": u"BSE",
    u"Symbol": u"500410",
    u"ExchSeg": u"bse_cm",
    u"Trsym": u"ACC"
  }
invalidList = {u"Status": u"cancelled",u"stat": u"Ok",}

#{u'stat': u'Not_Ok', u'emsg': u'API ERROR , ErrorCode : Session Expired'}
for k,v in invalidList.items():
    del output[k]
print output
output['warningList']=invalidList
print output

for inv in invalidList:
    #output.setdefault('Warning List') , [])
    output.setdefault('Warning List', [])
    output['Warning List'].append(inv)
    


yourString='        '
if yourString.strip()=='':
    print "yes"
strippedString = yourString.strip()

if strippedString=='':
    print "yes"
else:
    print 'no'








prop=Property()
propObj = prop.load_property_files('E:\\Investak\\investak.properties')


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
        else:
            sno = str(sno).strip()
        parameter = str(sheet.cell(rownum, 3).value).strip()
        description =(sheet.cell(rownum, 4).value).encode('utf-8').strip()
        businessTag =  str(sheet.cell(rownum, 5).value).strip()
        dataType = str(sheet.cell(rownum, 6).value).strip()
        validValues = sheet.cell(rownum, 7).value
        if dataType!='Decimal' and isinstance(validValues, float) and validValues.is_integer():
            validValues = int(validValues)
        else:
            validValues = str(validValues).strip()
        print 'validValues',validValues
        optional = str(sheet.cell(rownum, 8).value).strip()
        default = sheet.cell(rownum, 9).value
        if dataType!='Decimal' and isinstance(default, float) and default.is_integer():
            default = int(default)
        else:
            default = str(default).strip()
        print 'default',default
        transformation = str(sheet.cell(rownum, 10).value).strip()
        if dataType!='Decimal' and isinstance(transformation, float) and transformation.is_integer():
            transformation = int(transformation)
        else:
            transformation = str(transformation).strip()
        print 'transformation',transformation
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
    print 'exception',exception
    raise exception







    
import random
#float: 100001408.0
paramValue1='-0'
paramValue1=int(paramValue1)
paramValue1=abs(paramValue1)
print paramValue1

paramValue='-0.00'
try:
    splitNum=str(paramValue).split('.', 1)
    if(str(paramValue).isdigit()):
        pass
    if (isinstance (json.loads (str(paramValue)), (float))):
        pass
    if str(splitNum[1]).isdigit():
        pass
    if str(abs(int(splitNum[0]))).isdigit ():
        pass
except Exception as e:
    print e











my_date=datetime.now ()
r=int(my_date.toordinal() + 1721424.5)

print str(r)
#2457808.5


randomNo=random.randint(0,9)
print randomNo
print random.random() * 100
r = str(random.randint(0000,9999))
print r
print "%04d" % r


output='success'
output=json.loads(output)
print JsonResponse(output)

globvar = 0

def set_globvar_to_one():
    global globvar    # Needed to modify global copy of globvar
    globvar = 1

def print_globvar():
    print(globvar)     # No need for global declaration to read value of globvar

set_globvar_to_one()
print_globvar()  


expectLen=1
contentLen=2
if (expectLen != contentLen):
    print 'not match'
else:
    print 'match'
number=1.0
n= str(number).strip()
if type(n) == float:
    int(n)
print n
paramValue=100022269.35 #float: 100022269.35
if (isinstance (json.loads (str(paramValue)), (float))):
    pass

import time
paramValue='DAY1'
words=['NET1', ' DAY1', ' DAYNET']
if str(paramValue) in words:
    check = 0
    print 'ok'

'''
#date Time normal
date_text='16/02/2017 12:31:24'

try:
    time.strptime(date_text,'%d/%m/%Y %H:%M:%S')
    Date = True
except ValueError:
    Date = False
    Date = False
print 'ok'
'''
'''
#date Time month abbreviation
date_text='16-Feb-2017 10:30:33'

try:
    time.strptime(date_text,'%d-%b-%Y %H:%M:%S')
    Date = True
except ValueError:
    Date = False
print 'ok'
'''
#date  month abbreviation
date_text='16-Feb-2017'
if '-' in date_text:
    try:
        time.strptime(date_text,'%d-%b-%Y')
        Date = True
    except ValueError:
        Date = False
    print 'ok hyphen'
    
date_text='16/02/2017'
if '/' in date_text:
    #date normal 
    try:
        time.strptime(date_text,'%d/%m/%Y')
        Date = True
    except ValueError:
        Date = False
    print 'ok slash'


#Time normal
date_text='10:30:33'

try:
    time.strptime(date_text,'%H:%M:%S')
    Date = True
except ValueError:
    Date = False
print 'ok'


#--
# First make a datetime.datetime from 1985-02-17T06:00.
#--

'''dt = datetime.datetime ( 1985, 2, 17, 6 )
print "Input datetime:", dt

#--
# Convert to Julian Date and display.
#--

jd = JulianDate.fromDatetime(dt)
print float(jd)

#--
# Convert back to a datetime object and display that.
#--

check = jd.datetime()
print "Check datetime:", check
'''

'''date_object=datetime.strptime("8192009","%m%d%Y")
print date_object
#datetime.datetime(2009, 8, 19, 0, 0)
'''




import json
{
  "stat": "Not_Ok",
  "Emsg": "Session Expired"
}
[
  {
    "stat": "Not_Ok",
    "Emsg": "No Data"
  }
]
#ErrorCode  "Incorrect padding"
dict= {u'stat': u'Not_Ok', u'emsg': u'API ERROR , ErrorCode : Session Expired'}


output=[{  u'stat': u'Not_Ok',
    u'Emsg': u'Session Expired'
  }]

list=[]
print output[0].get('Emsg')
eMsg=output[0].get('Emsg')
list.append(eMsg)
print list
output[0]['Emsg']=list
print output
for k,v in output.items():
    print k
    print v









output=[{u'Status': u'rejected', u'stat': u'Ok', u'Nstordno': u'170126000000002', u'Exchange': u'BSE', u'Symbol': u'500477', u'ExchSeg': u'bse_cm', u'Trsym': u'ASHOKLEY'}, {u'Status': u'rejected', u'stat': u'Ok', u'Nstordno': u'170126000000001', u'Exchange': u'BSE', u'Symbol': u'500477', u'ExchSeg': u'bse_cm', u'Trsym': u'ASHOKLEY'}]
#output={'Status': 'rejected'}
 #find json array
Paramvalue='10.00'
''' 
if (Paramvalue.isdecimal()):
    print 'no error'
    pass
else:
    print 'error'
    '''
if (isinstance (json.loads (Paramvalue), (float))):
    print 'no error'
    pass
else: 
    print 'error'
    
  
    
    
if type(output) is list:
    print 'list'
    print len(output)
    for dict in output:
        print dict
else:
    print 'no list it is dict'

# if returns true, then JSON Array
#print 'list',isintance(output, list)

# if returns true, then JSON Object.
#print 'dict',isintance(output, dict)



content={u'stat': u'Not_Ok', u'Emsg': u'Session Expired'}
for param, value in content.items():
    print 'validValues', value

#string = "[0]  Invalid value. expected [1] available [2]"
param='logDevice'
validValues='AND,IOS'
paramValue='A'
ArrayValue=[param,validValues,paramValue]
arrlen=len(ArrayValue)


prop = Property ()
#prop_obj = prop.load_property_files('D:\\InvestAK\\investak.properties')  #hari
prop_obj = prop.load_property_files ('E:\\Investak\\investak\\investak.properties')  # ranjith

def readProperty(name):
    data=prop_obj.get (name)
    return data


arrayValue = ['hi','none']
#expectMsg = errorMsgCreate(readProperty('109'), arrayValue)

string=readProperty('109')
print 'string ',string
try:
    for index, item in enumerate (arrayValue):
        index = index
        if type(item)==int:
            item = str(item)
        newstr = string.replace('['+index+']',item)
        string = newstr
    print string
except Exception as e:
    print "exception is ",e
    #sendResponse(e)

    stat = readProperty ('NOT_OK')
    errorList = []
    errorMsg = e
    print errorMsg
    errorList.append(errorMsg)
    #sendErrorRequesterror(errorList,stat)

i=len(errorList)
print i
response_data = {}
for v in errorList:

    response_data.setdefault(readProperty('ERROR_MSG'),[])
    response_data[readProperty('ERROR_MSG')].append(v)
    response_data[readProperty('STATUS')] = stat

print 'response_data',response_data
print response_data"""