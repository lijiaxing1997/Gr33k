from PyQt5.Qt import QThread,pyqtSignal
import queue
import threading
import dns.resolver
import socket
import time
import plugins.config


class Subdomain(QThread):
    str_signal = pyqtSignal([str, str])
    int_signal = pyqtSignal([int, int])
    Queue = queue.Queue()
    Qsize = 0

    def __init__(self,domain,select_dns,dict,thread):
        super().__init__()
        self.domain = domain
        self.dns = select_dns
        self.thread = thread
        self.dict = dict
        self.timeout = 10
        self.resolver = dns.resolver.Resolver(configure=self.dns)
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout
        self.A_result = []
        self.CNAME_result = []

    def init_subdomain_dict(self):
        try:
            with open(self.dict,'r') as f:
                for line in f.readlines():
                    self.Queue.put(line.strip())
            self.Qsize = self.Queue.qsize()
            self.str_signal[str, str].emit('[+] 字典初始化完毕', 'green')
        except:
            self.str_signal[str,str].emit('[-] 没有找到字典文件','red')
            self.wait()

    def check_select_dns(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            server.connect((self.dns,53))
            self.str_signal[str, str].emit('[+] dns服务器连接成功', 'green')
            server.close()
        except:
            self.str_signal[str, str].emit('[-] 该dns服务器连接失败，请更换dns服务器', 'red')
            self.wait()

    def get_type_id(self, name):
        return dns.rdatatype.from_text(name)

    def query_thread(self):
        while not self.Queue.empty():
            if plugins.config.subdomain_wait == 0:
                subdomain = self.Queue.get()
                new_qsize = self.Queue.qsize()
                domain = subdomain + '.' + self.domain
                self.query_domain(domain)
                self.int_signal[int, int].emit(self.Qsize, new_qsize)
            else:
                time.sleep(1)
        self.int_signal[int, int].emit(self.Qsize, 0)

    def query_domain(self, domain):
        try:
            record = self.resolver.query(domain)
            for A_CNAME in record.response.answer:
                for item in A_CNAME.items:
                    if item.rdtype == self.get_type_id('A'):
                        self.str_signal[str, str].emit('[+] ' + domain + '-->A-->' + str(item), 'green')
                        self.A_result.append('[+] ' + domain + '-->A-->' + str(item))
                    elif (item.rdtype == self.get_type_id('CNAME')):
                        self.str_signal[str, str].emit('[+] ' + domain + '-->CNAME-->' + str(item), 'red')
                        self.CNAME_result.append('[+] ' + domain + '-->CNAME-->' + str(item))
        except:
            pass

    def run(self):
        self.init_subdomain_dict()
        self.check_select_dns()
        thread_list = []
        for i in range(int(self.thread)):
            thread = threading.Thread(target=self.query_thread)
            thread_list.append(thread)
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()
        self.str_signal[str, str].emit('[+] =================共计发现A记录 ' + str(self.A_result.__len__()) + ' 条=================', 'green')
        for A_line in self.A_result:
            self.str_signal[str, str].emit(A_line, 'green')
        self.str_signal[str, str].emit('[+] =================共计发现CNAME记录 ' + str(self.CNAME_result.__len__()) + ' 条=================', 'red')
        for CNAME_line in self.CNAME_result:
            self.str_signal[str, str].emit(CNAME_line, 'red')


