import requests
from zapv2 import ZAPv2 as ZAP
import time
import datetime
from os import getcwd

# Test Automation Part of the Script

target_url = 'https://stg.winnai.dev'
proxies = {
    'http': 'http://127.0.0.1:8090',
    'https': 'http://127.0.0.1:8090',
}

auth_dict = {'username': 'U_SECURITY_SCAN_4RUXQJK533', 'password': 'idui6sgt68oianb3iu4dy8o61vihwrwt'}

login = requests.post(target_url + '/auth/security-test-login',
                      proxies=proxies, json=auth_dict, verify=False)


if login.status_code == 200:  # if login is successful
    auth_token = login.headers['Authorization']
    auth_header = {"Authorization": auth_token}


# ZAP Operations
print("Zap Scan stat")
zap = ZAP(proxies={'http': 'http://localhost:8090',
                   'https': 'http://localhost:8090'})

if 'Light' not in zap.ascan.scan_policy_names:
    print("Adding scan policies")
    zap.ascan.add_scan_policy(
        "Light", alertthreshold="Medium", attackstrength="Low")

active_scan_id = zap.ascan.scan(target_url, scanpolicyname='Light')

print("active scan id: {0}".format(active_scan_id))

# now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print("Current Status of ZAP Active Scan: {0}%".format(
        zap.ascan.status(active_scan_id)))
    time.sleep(10)
print("Zap Scan end")
now = datetime.datetime.now().strftime("%m/%d/%Y")
alert_severity = 't;t;t;t'  # High;Medium;Low;Info
# CWEID;#WASCID;Description;Other Info;Solution;Reference;Request Header;Response Header;Request Body;Response Body
alert_details = 't;t;t;t;t;t;f;f;f;f'
source_info = 'Vulnerability Report for Winn.ai;Abhay Bhargav;API Team;{};{};v1;v1;API Scan Report'.format(
    now, now)
path = getcwd() + "/zap-report.json"
zap.exportreport.generate(path, "json", sourcedetails=source_info,
                          alertseverity=alert_severity, alertdetails=alert_details, scanid=active_scan_id)

zap.core.shutdown()