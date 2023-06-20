import time
from zapv2 import ZAPv2


target = 'https://stg.winnai.dev/'

zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8888', 'https': 'http://127.0.0.1:8888'})

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