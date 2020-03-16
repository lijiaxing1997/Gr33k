from PyQt5.Qt import QThread,pyqtSignal
import requests

class WeblogicCosole(QThread):
    headers = {'user-agent': 'Gr33k/v1.0'}

    signal = pyqtSignal([str, str])

    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port

    def islive(self,ur,port):
        url='http://' + str(ur)+':'+str(port)+'/console/login/LoginForm.jsp'
        try:
            r = requests.get(url, headers=self.headers)
        except:
            return 500
        return r.status_code

    def run(self):
        if self.islive(self.ip,self.port)==200:
            u='http://' + self.ip+':'+self.port +'/console/login/LoginForm.jsp'
            self.signal[str, str].emit("[+] Weblogic后台路径存在", 'red')
            self.signal[str, str].emit("[+] 执行完毕...end", 'green')
        else:
            self.signal[str, str].emit("[-] Weblogic后台路径不存在", 'green')
            self.signal[str, str].emit("[+] 执行完毕...end", 'green')
