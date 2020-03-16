from PyQt5.Qt import QThread,pyqtSignal
import queue
from threading import Thread
import time
import os
import plugins.config
import requests


class UrlScan(QThread):

    str_signal = pyqtSignal([str,str])
    progress_signal = pyqtSignal([int,int])

    def __init__(self,url,cookie,dict,thread_num,ignore_s=''):
        super().__init__()
        self.url = url
        self.header = {
            'cookie':cookie
        }
        if dict != "" and os.path.exists(dict):
            self.dict = dict
        else:
            self.str_signal[str,str].emit('[-] 未检测到您输入的路径','red')
            self.quit()
        self.thread_num = thread_num
        self.Queue = queue.Queue()
        self.sum_size = 0
        self.ignore_s = ignore_s


    def add_queue(self):
        self.str_signal[str, str].emit('[+] 初始化字典...', 'green')
        try:
            with open(self.dict,'r',encoding='utf8') as f:
                for line in f.readlines():
                    if line[0] == "":
                        pass
                    else:
                        self.Queue.put(line.strip())
        except:
            self.str_signal[str, str].emit('[-] 未检测到您输入的路径', 'red')
            self.quit()
        return self.Queue.qsize()


    def request_url(self):
        while not self.Queue.empty():
            if plugins.config.urlscan_wait == 0:
                Queue_size = self.Queue.qsize()
                part_url = self.Queue.get()
                try:
                    res = requests.get(url=self.url + part_url,headers=self.header,timeout=5)
                except Exception as err:
                    print(err)
                    continue
                if self.ignore_s == '':
                    if res.status_code == 200 or res.status_code == 302:
                        self.str_signal[str, str].emit('[+] [200] ' + self.url + part_url, 'green')
                else:
                    if self.ignore_s not in res.text:
                        if res.status_code == 200 or res.status_code == 302:
                            self.str_signal[str, str].emit('[+] [200] ' + self.url + part_url, 'green')
                self.progress_signal[int,int].emit(self.sum_size,Queue_size)
            else:
                time.sleep(1)
        self.str_signal[str, str].emit('[+] 执行完毕...', 'green')
        self.progress_signal[int, int].emit(1, 0)


    def run(self):
        thread_request_url_list = []
        self.sum_size = self.add_queue()
        for i in range(int(self.thread_num)):
            thread_request_url_list.append(Thread(target=self.request_url))
        for t in thread_request_url_list:
            t.start()
