from PyQt5.Qt import QThread,pyqtSignal
from plugins.tomcatlib.CVE_2020_1938 import CVE_2020_1938


def replace_str(response):
    response = response.replace("&", "&amp;")
    response = response.replace(">", "&gt;")
    response = response.replace("<", "&lt;")
    response = response.replace("\"", "&quot;")
    response = response.replace("\'", "&#39;")
    response = response.replace(" ", "&nbsp;")
    response = response.replace("\n", "<br>")
    return response

class Tomcat_(QThread):
    str_signal = pyqtSignal([str,str])

    def __init__(self,select_bug,target:str,target_file:str,port:int,active:str,file="WEB-INF/web.xml"):
        super().__init__()
        self.select_bug = select_bug
        self.target_file = target_file
        self.target = target
        self.port = port
        self.file = file
        self.active = active


    def CVE20201938_check(self,_2020_1938:CVE_2020_1938):
        try:
            if _2020_1938.check():
                self.str_signal[str, str].emit("[+] " + _2020_1938.target + ":" + str(_2020_1938.port) + " 存在漏洞", "red")
            else:
                self.str_signal[str, str].emit("[+] " + _2020_1938.target + ":" + str(_2020_1938.port) + " 不存在漏洞", "green")
        except:
            self.str_signal[str, str].emit("[+] " + _2020_1938.target + ":" + str(_2020_1938.port) + " 任务执行失败或不存在该漏洞", "green")

    def CVE20201938(self):
        if self.active == "check":
            if self.target != "":
                _2020_1938 = CVE_2020_1938(self.target, self.port, "WEB-INF/web.xml")
                self.CVE20201938_check(_2020_1938)
                self.str_signal[str, str].emit("[+] 执行完毕", 'green')
                return
            else:
                with open(self.target_file,'r') as f:
                    for line in f.readlines():
                        ip = line.strip()
                        _2020_1938 = CVE_2020_1938(ip, self.port, "WEB-INF/web.xml")
                        self.CVE20201938_check(_2020_1938)
                self.str_signal[str, str].emit("[+] 执行完毕", 'green')
                return
        else:
            _2020_1938 = CVE_2020_1938(self.target, self.port, self.file)
            result = _2020_1938.run()
            self.str_signal[str,str].emit(replace_str(result),'green')
            self.str_signal[str, str].emit("[+] 执行完毕", 'green')




    def run(self):
        if self.select_bug == "CVE-2020-1938":
            self.CVE20201938()
        else:
            pass


