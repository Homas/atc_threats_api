import requests
import time
import re
import socket
import os
import logging
import urllib3
urllib3.disable_warnings()
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

ATC_APIKey="PutYourAPIkeyHere"
Event_filter="" #"&source=rpz"
destinations=[{"type":"syslog", "host":"10.60.32.48","port":"514","facility":"local4","severity":"warning"},
              {"type":"syslog", "host":"10.60.32.65","port":"514","facility":"local4","severity":"warning"},
              #{"type":"outbound","host":"10.60.32.78","user":"admin","password":"infoblox","rule":"RPZ"}
             ]

sync_delay=60

t1=str(int(time.time())-60)
try:
  with open('atc_threats_ts.txt', 'r+') as f:
    t0=f.read().replace('\n', '')
    f.seek(0)
    f.write(t1)
except IOError, exc:
    if exc.errno == 2:
      t0=t1
      with open('atc_threats_ts.txt', 'w') as f:
        f.write(t1)
    else:
        raise
#for debug
#t0=str(int(time.time())-3600)

#Syslog RFCs
#https://tools.ietf.org/html/rfc5424
#https://tools.ietf.org/html/rfc5426

class Facility:
  local0, local1, local2, local3, local4, local5, local6, local7 = range(16, 24)

class Severity:
  emergency,alert,critical,error,warning,notice,informational,debug = range(8)

class DST:
  def __init__(self, *initial_data, **kwargs):
      for dictionary in initial_data:
          for key in dictionary:
              setattr(self, key, dictionary[key])
      for key in kwargs:
          setattr(self, key, kwargs[key])
      if self.type == "syslog":
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      if self.type == "outbound":
        resp = requests.get('https://'+self.host+'/wapi/v2.7/notification:rule?name='+self.rule+'&_return_fields=name,disable,event_type&_return_type=json', auth=(self.user, self.password),verify=False).json()
        if resp and not resp[0]["disable"]:
          self._ref='https://'+self.host+'/wapi/v2.7/'+resp[0]["_ref"]

#CEF:0|Infoblox|ATC|2.0||dns_event|10|InfobloxAtcTimestamp=2018-01-28T13:09:18.000Z InfobloxAtcDevice=52.196.166.33 InfobloxAtcThreatClass=FFX
#InfobloxAtcThreatProperty=depfile.us InfobloxAtcRcode=NXDOMAIN InfobloxAtcUser=unknown InfobloxAtcNetwork=qa_APAC_Client InfobloxAtcQname=depfile.us.
#InfobloxAtcQtype=A InfobloxAtcConfidence=HIGH InfobloxAtcFeedName=Threat Insight - Fast Flux InfobloxAtcFeedType=DOMAIN InfobloxAtcPolicyName=Default Global Policy
#InfobloxAtcRip=

  def send_msg_syslog(self,timestamp,msg):
    "send syslog"
    facility=getattr(Facility, self.facility)
    severity=getattr(Severity, self.severity)
    print self.type, self.host, timestamp, msg, "\n"
    data = "<%d>1 %s %s atc-sync %s - - %s" % (severity + facility*8, timestamp, socket.gethostname(),os.getpid(), msg)
    while True:
        try:
            self.socket.sendto(data, (self.host, int(self.port)))
            break
        except IOError, exc:
            if exc.errno == 55:
                time.sleep(0.1)
            else:
                raise
  
  def send_msg_outbound(self,timestamp,msg):
    "generate test outbound API notification"
    print self.type, self.host, timestamp, msg, "\n"
    r = re.search('InfobloxAtcTimestamp=([^\.]+)\..*InfobloxAtcQip=([^\s]+)\s.*InfobloxAtcQname=([^\s]+)\s.*InfobloxAtcFeedName=([^\s]+)\s.*InfobloxAtcFeedType=([^\s]+)\s.*InfobloxAtcQueryType=([^\s]+)\s.*', msg)
    #1 - timestamp, 2 - source_ip, 3 - query_name, 4 - feed, 5 - feed_type, 6 - qtype
    if r:
      payload={"_function":"trigger_outbound","event_text":'{"timestamp": "'+r.group(1)+'Z", \
        "source_ip": "'+r.group(2)+'", "query_name": "'+r.group(3)+'", "rule_name": "'+r.group(3)+'.'+r.group(4)+'", \
        "thread_id": 0, "sequence_id": 0, "vnode_oid": 0}'}
      resp = requests.post(self._ref, data=payload, auth=(self.user, self.password), verify=False)
      #print resp.text,payload
  
  def send_msg(self,timestamp,msg):
    "send a message to a remote system"
    method = getattr(self, 'send_msg_'+str(self.type))
    return method(timestamp,msg)

dest_DST=[DST(x) for x in destinations]

response = requests.get('https://csp.infoblox.com/api/threats/v1/dns_event?t0='+t0+'&t1='+t1+'&_format=cef'+Event_filter, headers={"Authorization": "Token "+ATC_APIKey})
for msg in response.text.encode('utf-8').split('\n'):
  r = re.search('InfobloxAtcTimestamp=([^\s]+)\s', msg)
  if r:
    for dst in dest_DST:
      dst.send_msg(r.group(1),msg)

print 'curl -k -H  "Authorization: Token '+ATC_APIKey+'" "https://csp.infoblox.com/api/threats/v1/dns_event?t0='+t0+'&t1='+t1+'&_format=cef"\n'
