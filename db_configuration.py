url = 'https://www.virustotal.com/vtapi/v2/url/report'
apikey = 'YOUR_API_KEY'
url_file ='C:\\Users\\mardm\\PycharmProjects\\hw\\data\\urls\\request1.csv'

#sql connect 
db_name='main_db'
table = 'url_risk'

import mysql.connector
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="YOUR_PASSWORD",
)