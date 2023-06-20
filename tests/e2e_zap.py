import time
from zapv2 import ZAPv2
import datetime
from os import getcwd
import json2html
import json

target = 'https://stg.winnai.dev/'

zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

zap.context.import_context("/file/context")

print ('Accessing target %s' % target)
zap.urlopen(target)
time.sleep(2)

print ('Spidering target %s' % target)
scanid = zap.spider.scan(target)

time.sleep(2)

print ('Spider completed')

time.sleep(5)

print ('Scanning target %s' % target)
scanid = zap.ascan.scan(target)

print ('Scan completed')

now = datetime.datetime.now().strftime("%m/%d/%Y")
alert_severity = 't;t;t;t'  # High;Medium;Low;Info
# CWEID;#WASCID;Description;Other Info;Solution;Reference;Request Header;Response Header;Request Body;Response Body
alert_details = 't;t;t;t;t;t;f;f;f;f'
source_info = 'Vulnerability Report for Winn.ai;Abhay Bhargav;API Team;{};{};v1;v1;API Scan Report'.format(
    now, now)
path = getcwd() + "/zap-report.json"
zap.exportreport.generate(path, "json", sourcedetails=source_info,
                          alertseverity=alert_severity, alertdetails=alert_details, scanid=scanid)
infoFromJson = json.loads(path)
html_response=(json2html.convert(json = infoFromJson))
with open("sample.html", "w") as html_file:
    html_file.write(html_response.text)

zap.core.shutdown()