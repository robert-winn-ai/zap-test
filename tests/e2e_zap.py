import time
from zapv2 import ZAPv2
import datetime
from os import getcwd
from json2html import *
import json
import sys

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

def create(JsonResponse):
    jsonFile = 'testFile.json'
    with open(jsonFile, 'w') as json_data:
        json.dump(JsonResponse, json_data)
    with open('testFile.json') as json_data:
        infoFromJson = json.load(json_data)
        scanOutput = json2html.convert(json=infoFromJson)
        htmlReportFile = 'Report.html'
        with open(htmlReportFile, 'w') as htmlfile:
            htmlfile.write(str(scanOutput))
JsonResponse=json2html.convert(json = infoFromJson)
create(JsonResponse)
zap.core.shutdown()