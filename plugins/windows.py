from PyQt5.Qt import QThread,pyqtSignal
from plugins.windowslib.CVE_2020_0796 import CVE20200796
from netaddr import IPNetwork
from plugins.windowslib.MS17010 import MS17010





class Windows(QThread):

    str_signal = pyqtSignal([str,str])

    def __init__(self,ip,port,cmd,select_bug,active):
        super().__init__()
        self.ip = ip
        self.port = port
        self.select_bug = select_bug
        self.active = active
        self.cmd = cmd

    def CVE_2020_0796(self):
        if self.active == "scan":
            for ip in IPNetwork(self.ip):
                try:
                    cve20200796 = CVE20200796(self.ip)
                    result_state = cve20200796.scan()
                except:
                    self.str_signal[str, str].emit("[-]  执行出错", "red")
                    return
                if result_state:
                    self.str_signal[str,str].emit("[+] " + str(ip) + " 存在CVE-2020-0796漏洞","red")
                else:
                    self.str_signal[str, str].emit("[-] " + str(ip) + " 不存在CVE-2020-0796漏洞","green")
        else:
            self.str_signal[str, str].emit("[-] 暂时不支持CVE-2020-0796漏洞的命令执行", "red")

    def MS_17010(self):
        if self.active == "scan":
            for ip in IPNetwork(self.ip):
                try:
                    ms17010 = MS17010(ip=self.ip,port=self.port)
                    result_state = ms17010.scan()
                except:
                    self.str_signal[str, str].emit("[-]  执行出错", "red")
                    return
                if result_state:
                    self.str_signal[str,str].emit("[+] " + str(ip) + " 存在ms17010漏洞","red")
                else:
                    self.str_signal[str, str].emit("[-] " + str(ip) + " 不存在ms17010漏洞","green")
        else:
            self.str_signal[str, str].emit("[-] 暂时不支持ms17010漏洞的命令执行", "red")

    def run(self):
        if self.select_bug == "CVE-2020-0796":
            self.CVE_2020_0796()
        if self.select_bug == "MS17010":
            self.MS_17010()