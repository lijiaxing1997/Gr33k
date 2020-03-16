import shodan
from PyQt5.Qt import QThread,pyqtSignal
from PyQt5.QtGui import QStandardItemModel,QStandardItem

class Shodan_handle(QThread):
    str_signal = pyqtSignal([str,str])

    def __init__(self,key,keyword:str):
        super().__init__()
        self.SHODAN_API_KEY = key
        self.keyword = keyword
        self.api = shodan.Shodan(self.SHODAN_API_KEY)

    def search(self,country:str):
        if country == 'NULL':
            results = self.api.search(self.keyword)
        else:
            results = self.api.search(self.keyword + ' country:"' + country + '"' )
        total = int(results['total'])
        rows = results['matches'].__len__()
        module = QStandardItemModel(rows, 4)
        module.setHorizontalHeaderLabels(['IP地址','主机名', '域名', '位置'])
        for row in range(rows):
            for col in range(4):
                item0 = QStandardItem(str(results['matches'][row]['ip_str']))
                module.setItem(row, 0, item0)
                item1 = QStandardItem(str(results['matches'][row]['hostnames']))
                module.setItem(row, 1, item1)
                item2 = QStandardItem(str(results['matches'][row]['domains']))
                module.setItem(row, 2, item2)
                item3 = QStandardItem(str(results['matches'][row]['location']['city']))
                module.setItem(row, 3, item3)
        return total,module

    def query_host(self,ip):
        host = self.api.host(ip)
        ports = host['ports']
        host_info = {
            'org':host['data'][0]['org'],
            'isp':host['data'][0]['isp'],
            'timestamp':host['data'][0]['timestamp']
        }
        port_info = {}
        for data in host['data']:
            try:
                port = str(data['port'])
                product = data['product']
            except:
                continue
            port_info[port] = product
        return [str(i) for i in ports],host_info,port_info

    def query_port(self,ip,port):
        host = self.api.host(ip)
        for data in host['data']:
            if str(port) == str(data['port']):
                try:
                    title = data['http']['title']
                    html = data['http']['html']
                    return str(title) +'\r\n' + str(html)
                except:
                    return data['data']


    def run(self):
        pass