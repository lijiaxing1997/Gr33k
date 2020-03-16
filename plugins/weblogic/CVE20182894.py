import requests
from PyQt5.Qt import QThread,pyqtSignal




class CVE20182894(QThread):
    signal = pyqtSignal([str, str])
    VUL = ['CVE-2018-2894']
    headers = {'user-agent': 'Gr33k/v1.0'}
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.index = 0

    def islive(self,ur,port):
        url='http://' + str(ur)+':'+str(port)+'/ws_utc/resources/setting/options/general'
        try:
            r = requests.get(url, headers=self.headers)
        except:
            return 404
        return r.status_code

    def run(self):
        if self.islive(self.ip,self.port)!=404:
            self.signal[str, str].emit('[+] CVE-2018-2894 漏洞存在', 'red')
        else:
            self.signal[str, str].emit('[-] CVE-2018-2894 漏洞不存在', 'green')
