import requests
import json
import db_configuration
from collections import Counter
import datetime
from db_configuration import mydb
import time

apikey=db_configuration.apikey  
url=db_configuration.url 
db_name=db_configuration.db_name 
table=db_name+'.'+db_configuration.table 
url_file=db_configuration.url_file

def setup (db_name,table) :
    mydb.cursor().execute("CREATE SCHEMA IF NOT EXISTS " + db_name + ";")
    mydb.cursor().execute("CREATE TABLE IF NOT EXISTS  {} (\
   `dt` DATETIME NOT NULL,\
   `url` VARCHAR(45) NOT NULL,\
   `Site_Risk` VARCHAR(45) NULL,\
   `clean` INT NULL,\
   `unrated` INT NULL,\
   `malicious` INT NULL,\
   `malware` INT NULL,\
   `phishing` INT NULL,\
   PRIMARY KEY ( `url`));\
  ".format(table))
   
def read_from_db(select):
    print(select)
    mycursor = mydb.cursor()
    mydb.cursor().execute(select)
    myresult = mycursor.fetchall()
    for x in myresult:
        print(x)
    return myresult

def write_to_db(insert,val):
    mydb.cursor().execute(insert, val)
    mydb.commit()
    print(mydb.cursor().rowcount, "record inserted.")

def get_url_data(ApiUrl, ApiKey, URL):
    params = {'apikey': ApiKey, 'resource': ApiUrl }
    return requests.get(URL, params=params)

def Site_Risk(malicious, malware, phishing):
    if max(malicious, malware, phishing) > 0:
        return 'risk'
    return 'safe'

def status_code_error(rerun, data):
    status_code = data.status_code
    if status_code == 404:
         raise Exception("status.code=404 api is not found, check  your Request-URI or try again later")
    elif status_code == 403:
         raise Exception("status.code=403, You don't have enough privileges to make the request (check your API key)")
    elif status_code == 400:
        raise Exception("status.code=400, Bad request. Your request was somehow incorrect")
    
    elif status_code == 204:
        if rerun==0:
            for count in range(10):
                print(time.ctime())
                time.sleep(6)
            update_data(dt, url, apikey, l, 1)
        else:
            raise Exception('Request rate limit exceeded exit after one rerun')
    elif data.json():
        print('{} :  skipping(no data on url) {} status.code={}'.format(dt, l.strip(), data.status_code))
    else:
        raise Exception('something went wrong')

def update_data(dt, url, api, l,rerun):
    try:
        data = get_url_data(url, apikey, l)
        res = data.json()['scans']
        counts = Counter([res[key]['result'] for key in res])
        clean = counts['clean site']
        unrated = counts['unrated site']
        malicious = counts['malicious site']
        malware = counts['malware site']
        phishing = counts['phishing site']
        insert= 'replace into {} (dt,url,`Site_Risk`,clean,unrated,malicious,malware,phishing) VALUES (%s, %s,%s,%s,%s,%s,%s,%s)'.format(table)
        val= (dt,l.strip(),Site_Risk(malicious, malware, phishing), clean , unrated , malicious , malware , phishing )
        write_to_db(insert,val)
        print(val)
    except:
        status_code_error(rerun,data) 

setup (db_name,table)
file1 = open(url_file, 'r') 
Lines = file1.readlines()

for l in Lines:
    l=l.strip()
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    select = "select * from {} where url='{}' and dt>='{}'- INTERVAL 30 MINUTE; ;".format(table,l,dt)
    res = read_from_db(select)
    if res:
        print('data for url= `{}` is up2date'.format(l))
        continue    
    update_data(dt, url, apikey, l,0)
   