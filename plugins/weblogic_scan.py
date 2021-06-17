from plugins.weblogic.CVE20144210 import SSRF
from plugins.weblogic.CVE20160638 import CVE20160638
from plugins.weblogic.CVE20163510 import CVE20163510
from plugins.weblogic.CVE20173248 import CVE20173248
from plugins.weblogic.CVE20173506 import CVE20173506
from plugins.weblogic.CVE20182628 import CVE20182628
from plugins.weblogic.CVE20182893 import CVE20182893
from plugins.weblogic.CVE20182894 import CVE20182894
from plugins.weblogic.CVE20192618 import CVE20192618
from plugins.weblogic.CVE20192725 import CVE20192725
from plugins.weblogic.CVE20192729 import CVE20192729
from plugins.weblogic.CVE201710271 import CVE201710271
from plugins.weblogic.CVE202014882 import CVE202014882
from plugins.weblogic.WeblogicConsole import WeblogicCosole
from PyQt5.Qt import QThread


class Weblogic_Scan(QThread):
    def __init__(self,ip,port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.ssrf = SSRF(self.ip, self.port)
        self.cve20160638 = CVE20160638(self.ip, self.port)
        self.cve20163510 = CVE20163510(self.ip, self.port)
        self.cve20173248 = CVE20173248(self.ip, self.port)
        self.cve20173506 = CVE20173506(self.ip, self.port)
        self.cve20182628 = CVE20182628(self.ip, self.port)
        self.cve20182893 = CVE20182893(self.ip, self.port)
        self.cve20182894 = CVE20182894(self.ip, self.port)
        self.cve20192618 = CVE20192618(self.ip, self.port)
        self.cve20192725 = CVE20192725(self.ip, self.port)
        self.cve20192729 = CVE20192729(self.ip, self.port)
        self.cve201710271 = CVE201710271(self.ip, self.port)
        self.cve202014882 = CVE202014882(self.ip,self.port,'')
        self.weblogiccosole = WeblogicCosole(self.ip, self.port)

    def run(self):
        self.ssrf.run()
        self.cve20160638.run()
        self.cve20163510.run()
        self.cve20173248.run()
        self.cve20173506.run()
        self.cve20182628.run()
        self.cve20182893.run()
        self.cve20182894.run()
        self.cve20192618.run()
        self.cve20192725.run()
        self.cve20192729.run()
        self.cve201710271.run()
        self.weblogiccosole.run()
        self.cve202014882.run()
