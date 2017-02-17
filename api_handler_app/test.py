from properties.p import Property
import datetime

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
print response_data