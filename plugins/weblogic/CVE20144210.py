import requests
from PyQt5.Qt import QThread,pyqtSignal


class SSRF(QThread):
    headers = {'user-agent': 'Gr33k:v1.0'}
    signal = pyqtSignal([str,str])

    def __init__(self,ip,port):
        super().__init__()
        self.ip = ip
        self.port = port

    def islive(self):
        url='http://' + self.ip +':'+self.port+'/uddiexplorer/'
        try:
            r = requests.get(url, headers=self.headers)
        except:
            return 500
        return r.status_code

    def run(self):
        if self.islive()==200:
            u='http://' + self.ip +':'+ self.port + '/uddiexplorer/'
            self.signal[str,str].emit('[+] SSRF 漏洞存在 ' + u,'red')
        else:
            self.signal[str,str].emit('[-] SSRF 漏洞不存在','green')