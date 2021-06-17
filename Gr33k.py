import sys
import fix_qt_import_error
from PyQt5.QtWidgets import QApplication, QMainWindow,QMessageBox,QFileDialog,QHeaderView,QAbstractItemView
from PyQt5.QtGui import QIcon,QStandardItemModel,QStandardItem
from PyQt5.QtCore import QModelIndex,QStringListModel
from weblogic_gui import Ui_MainWindow
from plugins.weblogic_scan import Weblogic_Scan
from plugins.weblogic_exe import Weblogic_Exe
from plugins.struts2 import Struts2
from plugins.url_scan import UrlScan
from plugins.brute.Brute_ssh import Brute_ssh
from plugins.brute.Brute_ftp import Brute_ftp
from plugins.brute.Brute_mysql import Brute_mysql
from plugins.brute.Brute_telnet import Brute_telnet
from plugins.port_scan import Port_Scan
from plugins.subdomain import Subdomain
from plugins.unauthorized import Unauthorized,Request_dict
from plugins.XSStrike.t_xss import Arg,XSS
import plugins.XSStrike.core.config
from plugins.pyshodan import Shodan_handle
from plugins.ssh_username import Ssh_username
import plugins.config
from plugins.slowhttp import Slowhttp
from plugins.apache_rce import ApacheCve
from plugins.use_sqlmap import Use_sqlmap
from plugins.jboss import Jboss
from plugins.windows import Windows
from plugins.tomcat import Tomcat_

class MyWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.setupUi(self)
        self.load_event()

    def print_weblogic_result(self,str,color):
        self.plainTextEdit_weblogic_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')

    def print_struts2_result(self,str,color):
        self.plainTextEdit_struts2_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_urlscan_result(self,str,color):
        self.plainTextEdit_urlscan_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_urlscan_progress(self,sum_size,qsize):
        value = (sum_size - qsize) / sum_size * 100
        self.progressBar_urlscan_progress.setValue(value)
    def print_brute_result(self,str,color):
        self.plainTextEdit_brute_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_portscan_result(self,str,color):
        self.plainTextEdit_portscan_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_portscan_progress(self,sum_size,qsize):
        value = (sum_size - qsize) / sum_size * 100
        self.progressBar_portscan_progress.setValue(value)
    def print_submain_result(self,str,color):
        self.plainTextEdit_submain_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_subdomain_progress(self,sum_size,qsize):
        value = (sum_size - qsize) / sum_size * 100
        self.progressBar_subdomain_progress.setValue(value)
    def print_unauthorized_result(self,str,color):
        self.plainTextEdit_unauthorized_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def finished_result(self):
        self.plainTextEdit_weblogic_result.appendHtml('<span style="color:green;">[+] 执行完毕...end</span>')
    def print_xss_result(self,str,color):
        self.plainTextEdit_xss_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_xss_payload(self, str):
        self.plainTextEdit_xss_payload.appendHtml('<span style="color:red;">' + str + '</span>')
    def print_shodan_log(self,str,color):
        self.plainTextEdit_shodan_log.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_shodan_hostinfo(self,str,color):
        self.plainTextEdit_shodan_hostinfo.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_sshusername_result(self,str,color):
        self.plainTextEdit_sshusername_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_sshusername_progress(self,sum_size,qsize):
        value = (sum_size - qsize) / sum_size * 100
        self.progressBar_sshusername_progress.setValue(value)
    def print_slowhttp_result(self,str,color):
        self.plainTextEdit_slowhttp_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_apache_result(self,str,color):
        self.plainTextEdit_apache_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_jboss_result(self,str,color):
        self.plainTextEdit_jboss_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')

    def print_sqlmap_result(self, str, color):
        self.plainTextEdit_sqlmap_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')

    def print_sqlmap_sysinfo(self, str, color):
        self.plainTextEdit_sqlmap_sysinfo.appendHtml('<span style="color:' + color + ';">' + str + '</span>')

    def print_windows_result(self, str, color):
        self.plainTextEdit_windows_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')
    def print_tomcat_2020_1938_result(self, str, color):
        self.plainTextEdit_tomcat_2020_1938_result.appendHtml('<span style="color:' + color + ';">' + str + '</span>')

    def load_event(self):
        def weblogic_start_chlicked():
            self.plainTextEdit_weblogic_result.setPlainText("")
            self.plainTextEdit_weblogic_result.appendHtml('<span style="color:green;">[+] -----------开始检测-----------</span>')
            weblogic_ip = self.lineEdit_weblogic_ip.text()
            weblogic_port = self.lineEdit_weblogic_port.text()
            if weblogic_ip != "" and weblogic_port != "":
                weblogic_scan = Weblogic_Scan(weblogic_ip,weblogic_port)
                weblogic_scan.ssrf.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20160638.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20163510.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20173248.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20173506.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20182628.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20182893.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20182894.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20192618.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20192725.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve20192729.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve201710271.signal.connect(self.print_weblogic_result)
                weblogic_scan.weblogiccosole.signal.connect(self.print_weblogic_result)
                weblogic_scan.cve202014882.signal.connect(self.print_weblogic_result)
                weblogic_scan.start()
                weblogic_scan.exec()
            else:
                reply = QMessageBox.critical(self, '错误', '对不起，ip与port不能为空！', QMessageBox.Yes, QMessageBox.Yes)

        self.pushButton_weblogic_start.clicked.connect(weblogic_start_chlicked)
        def weblogic_exe_clicked():
            self.plainTextEdit_weblogic_result.setPlainText("")
            weblogic_ip = self.lineEdit_weblogic_ip.text()
            weblogic_port = self.lineEdit_weblogic_port.text()
            cmd = self.lineEdit_weblogic_cmd.text()
            bug = self.comboBox_weblogic_bug.currentText()
            if weblogic_ip != "" and weblogic_port != "":
                weblogic_exe = Weblogic_Exe(weblogic_ip,weblogic_port,bug,cmd,'cmd_exe')
                weblogic_exe.str_signal.connect(self.print_weblogic_result)
                weblogic_exe.start()
                weblogic_exe.exec()
        self.pushButton_weblogic_exe.clicked.connect(weblogic_exe_clicked)
        def weblogic_uploadshell_clicked():
            self.plainTextEdit_weblogic_result.setPlainText("")
            weblogic_ip = self.lineEdit_weblogic_ip.text()
            weblogic_port = self.lineEdit_weblogic_port.text()
            cmd = self.lineEdit_weblogic_cmd.text()
            bug = self.comboBox_weblogic_bug.currentText()
            if weblogic_ip != "" and weblogic_port != "":
                weblogic_exe = Weblogic_Exe(weblogic_ip, weblogic_port, bug, cmd, 'upload_shell')
                weblogic_exe.str_signal.connect(self.print_weblogic_result)
                weblogic_exe.start()
                weblogic_exe.exec()
        self.pushButton_weblogic_uploadshell.clicked.connect(weblogic_uploadshell_clicked)

        def struts2_scan_start_clicked():
            self.plainTextEdit_struts2_result.setPlainText("")
            self.plainTextEdit_struts2_result.appendHtml('<span style="color:green;">[+] -----------开始扫描struts2-----------</span>')
            struts2_url = self.lineEdit_struts2_url.text()
            struts2_cookie = self.lineEdit_struts2_cookie.text()
            if struts2_url != "":
                struts2 = Struts2(struts2_url,struts2_cookie,"scan",None,"")
                struts2.signal.connect(self.print_struts2_result)
                struts2.start()
                struts2.exec()
            else:
                reply = QMessageBox.critical(self, '错误', '对不起，url不能为空！', QMessageBox.Yes, QMessageBox.Yes)


        self.pushButton_struts2_scan.clicked.connect(struts2_scan_start_clicked)

        def struts2_exe_clicked():
            self.plainTextEdit_struts2_result.setPlainText("")
            self.plainTextEdit_struts2_result.appendHtml('<span style="color:green;">[+] -----------命令执行struts2-----------</span>')
            struts2_url = self.lineEdit_struts2_url.text()
            struts2_cookie = self.lineEdit_struts2_cookie.text()
            cmd = self.lineEdit_struts2_cmd.text()
            select_bug = self.comboBox_strust2_bug.currentText()
            if struts2_url != "" and cmd != "":
                struts2 = Struts2(struts2_url, struts2_cookie, "exe_cmd", select_bug,cmd)
                struts2.signal.connect(self.print_struts2_result)
                struts2.start()
                struts2.exec()
            else:
                reply = QMessageBox.critical(self, '错误', '对不起，url或者命令窗口不能为空！', QMessageBox.Yes, QMessageBox.Yes)
        self.pushButton_struts2_exe.clicked.connect(struts2_exe_clicked)

        def url_scan_start():
            plugins.config.urlscan_wait = 0
            self.plainTextEdit_urlscan_result.setPlainText("")
            self.plainTextEdit_urlscan_result.appendHtml('<span style="color:green;">[+] -----------开始执行路径扫描-----------</span>')
            urlscan_url = self.lineEdit_urlscan_url.text()
            urlscan_cookie = self.lineEdit_urlscan_cookie.text()
            urlscan_dict = self.lineEdit_urlscan_dict.text()
            urlscan_thread_num = self.comboBox_urlscan_thread.currentText()
            if urlscan_url == "":
                reply = QMessageBox.critical(self, '错误', '对不起，url不能为空！', QMessageBox.Yes, QMessageBox.Yes)
            else:
                if self.plainTextEdit_urlscan_ignore == '':
                    urlsan = UrlScan(urlscan_url,urlscan_cookie,urlscan_dict,urlscan_thread_num)
                else:
                    ignore_s = self.plainTextEdit_urlscan_ignore.toPlainText()
                    urlsan = UrlScan(urlscan_url, urlscan_cookie, urlscan_dict, urlscan_thread_num,ignore_s=ignore_s)
                urlsan.str_signal.connect(self.print_urlscan_result)
                urlsan.progress_signal.connect(self.print_urlscan_progress)
                urlsan.start()
                urlsan.exec()

        self.pushButton_urlscan_start.clicked.connect(url_scan_start)

        def urlscan_stop_clicked():
            if plugins.config.urlscan_wait == 0:
                plugins.config.urlscan_wait = 1
                self.pushButton_urlscan_stop.setText('继续')
            else:
                plugins.config.urlscan_wait = 0
                self.pushButton_urlscan_stop.setText('暂停')

        self.pushButton_urlscan_stop.clicked.connect(urlscan_stop_clicked)

        def urlscan_choice_clicked():
            url_dict = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_urlscan_dict.setText(url_dict[0])

        self.pushButton_urlscan_choice.clicked.connect(urlscan_choice_clicked)

        def brute_set_iplist_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_brute_iplist.setText(openfile_name[0])
        def brute_set_usernamelist_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_brute_usernamelist.setText(openfile_name[0])
        def brute_set_passwdlist_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_brute_passwdlist.setText(openfile_name[0])
        self.pushButton_brute_set_iplist.clicked.connect(brute_set_iplist_clicked)
        self.pushButton_brute_set_usernamelist.clicked.connect(brute_set_usernamelist_clicked)
        self.pushButton_brute_set_passwdlist.clicked.connect(brute_set_passwdlist_clicked)

        def brute_start():
            plugins.config.brute_wait = 0
            self.plainTextEdit_brute_result.setPlainText("")
            self.plainTextEdit_brute_result.appendHtml('<span style="color:green;">[+] 开始执行暴力破解</span>')
            brute_ip = self.lineEdit_brute_ip.text()
            brute_port = self.lineEdit_brute_port.text()
            brute_thread = self.comboBox_brute_thread.currentText()
            brute_iplist = self.lineEdit_brute_iplist.text()
            brute_usernamelist = self.lineEdit_brute_usernamelist.text()
            brute_passwordlist = self.lineEdit_brute_passwdlist.text()
            if brute_port == "":
                reply = QMessageBox.critical(self, '错误', 'port不能为空！', QMessageBox.Yes, QMessageBox.Yes)
            if self.radioButton_brute_ssh.isChecked():
                self.plainTextEdit_brute_result.appendHtml(
                    '<span style="color:green;">[+] SSH暴力破解</span>')
                ssh =  Brute_ssh(brute_ip,brute_iplist,brute_usernamelist,brute_port,brute_passwordlist,brute_thread)
                ssh.str_signal.connect(self.print_brute_result)
                ssh.start()
                ssh.exec()
            if self.radioButton_brute_ftp.isChecked():
                self.plainTextEdit_brute_result.appendHtml(
                    '<span style="color:green;">[+] FTP暴力破解</span>')
                ftp = Brute_ftp(brute_ip,brute_iplist,brute_usernamelist,brute_port,brute_passwordlist,brute_thread)
                ftp.str_signal.connect(self.print_brute_result)
                ftp.start()
                ftp.exec()
            if self.radioButton_brute_mysql.isChecked():
                self.plainTextEdit_brute_result.appendHtml(
                    '<span style="color:green;">[+] MYSQL暴力破解</span>')
                mysql = Brute_mysql(brute_ip,brute_iplist,brute_usernamelist,brute_port,brute_passwordlist,brute_thread)
                mysql.str_signal.connect(self.print_brute_result)
                mysql.start()
                mysql.exec()
            if self.radioButton_brute_telnet.isChecked():
                self.plainTextEdit_brute_result.appendHtml(
                    '<span style="color:green;">[+] TELNET暴力破解</span>')
                telnet = Brute_telnet(brute_ip,brute_iplist,brute_usernamelist,brute_port,brute_passwordlist,brute_thread)
                telnet.str_signal.connect(self.print_brute_result)
                telnet.start()
                telnet.exec()

        self.pushButton_brute_start.clicked.connect(brute_start)

        def brute_stop_clicked():
            if plugins.config.brute_wait == 0:
                plugins.config.brute_wait = 1
                self.pushButton_brute_stop.setText('继续')
            else:
                plugins.config.brute_wait = 0
                self.pushButton_brute_stop.setText('暂停')
        self.pushButton_brute_stop.clicked.connect(brute_stop_clicked)

        def portscan_start_clicked():
            plugins.config.portscan_wait = 0
            self.plainTextEdit_portscan_result.setPlainText('')
            ip = self.lineEdit_portscan_ip.text()
            ip_list = self.lineEdit_portscan_file.text()
            thread = self.comboBox_portscan_thread.currentText()
            ports = self.lineEdit_portscan_port.text()
            if ports != '':
                port_scan = Port_Scan(ip, ports, int(thread),ip_list)
                port_scan.str_signal.connect(self.print_portscan_result)
                port_scan.int_signal.connect(self.print_portscan_progress)
                port_scan.start()
                port_scan.exec()
            elif self.radioButton_portscan_radioall.isChecked():
                port_scan = Port_Scan(ip,'all',int(thread),ip_list)
                port_scan.str_signal.connect(self.print_portscan_result)
                port_scan.int_signal.connect(self.print_portscan_progress)
                port_scan.start()
                port_scan.exec()
            elif self.radioButton_portscan_radio1000.isChecked():
                port_scan = Port_Scan(ip, 'top1000', int(thread),ip_list)
                port_scan.str_signal.connect(self.print_portscan_result)
                port_scan.int_signal.connect(self.print_portscan_progress)
                port_scan.start()
                port_scan.exec()


        self.pushButton_portscan_start.clicked.connect(portscan_start_clicked)
        def portscan_selectfile_clicked():
            file_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_portscan_file.setText(file_name[0])

        self.pushButton_portscan_selectfile.clicked.connect(portscan_selectfile_clicked)
        def portscan_stop_clicked():
            if plugins.config.portscan_wait == 0:
                plugins.config.portscan_wait = 1
                self.pushButton_portscan_stop.setText('继续')
            else:
                plugins.config.portscan_wait = 0
                self.pushButton_portscan_stop.setText('暂停')

        self.pushButton_portscan_stop.clicked.connect(portscan_stop_clicked)
        def subdomain_start_clicked():
            self.plainTextEdit_submain_result.setPlainText('')
            domain = self.lineEdit_subdomain_domain.text()
            dict = self.lineEdit_subdomian_dict.text()
            thread = self.comboBox_subdomain_thread.currentText()
            if self.lineEdit_subdomain_setdns.text() == '':
                dns = self.comboBox_subdomain_dns.currentText()
            else:
                dns = self.lineEdit_subdomain_setdns.text()
            subdomain = Subdomain(domain,dns,dict,thread)
            subdomain.str_signal.connect(self.print_submain_result)
            subdomain.int_signal.connect(self.print_subdomain_progress)
            subdomain.start()
            subdomain.exec()

        self.pushButton_subdomain_start.clicked.connect(subdomain_start_clicked)
        def subdoamin_selectdict_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_subdomian_dict.setText(openfile_name[0])

        self.pushButton_subdomian_selectdict.clicked.connect(subdoamin_selectdict_clicked)
        def subdomain_stop_clicked():
            if plugins.config.subdomain_wait == 0:
                plugins.config.subdomain_wait = 1
                self.pushButton_subdomain_stop.setText('继续')
            else:
                plugins.config.subdomain_wait = 0
                self.pushButton_subdomain_stop.setText('暂停')

        self.pushButton_subdomain_stop.clicked.connect(subdomain_stop_clicked)

        def unauthorized_allparam_clicked():
            self.plainTextEdit_unauthorized_data1response.setPlainText('等待返回...')
            self.plainTextEdit_unauthorized_data2response.setPlainText('等待返回...')
            data1request = self.plainTextEdit_unauthorized_data1request.toPlainText().split('\n')
            data2request = self.plainTextEdit_unauthorized_data2request.toPlainText().split('\n')
            try:
                request1_dict = Unauthorized.init_request_param(data1request)
                request2_dict = Unauthorized.init_request_param(data2request)
                get_param1,post_param1,cookie1= Unauthorized.get_params_name(request1_dict)
                get_param2,post_param2,cookie2 = Unauthorized.get_params_name(request2_dict)
                if get_param1 == get_param2 and post_param1 == post_param2 and cookie1 == cookie2 or request1_dict.url != request2_dict.url:
                    self.lineEdit_unauthorized_getparam.setText(get_param1)
                    self.print_unauthorized_result('[+] 获取到get参数: ' + get_param1, 'green')
                    self.lineEdit_unauthorized_postparam.setText(post_param1)
                    self.print_unauthorized_result('[+] 获取到post参数: ' + post_param1, 'green')
                    self.lineEdit_unauthorized_cookieparam.setText(cookie1)
                    self.print_unauthorized_result('[+] 获取到cookie参数: ' + cookie1, 'green')
                    self.print_unauthorized_result('[+] 参数初始化完毕','green')
                    try:
                        response1,response1_body = Unauthorized.send_query(request1_dict)
                        # self.plainTextEdit_unauthorized_data1response.setPlainText(response1)
                        self.print_unauthorized_result('[+] request1初始化请求完毕', 'green')
                    except Exception as err:
                        print(err)
                        self.print_unauthorized_result('[-] request1初始化请求失败', 'red')
                        return
                    try:
                        response2,response2_body = Unauthorized.send_query(request2_dict)
                        # self.plainTextEdit_unauthorized_data2response.setPlainText(response2)
                        self.print_unauthorized_result('[+] request2初始化请求完毕', 'green')
                    except:
                        self.print_unauthorized_result('[-] request2初始化请求失败', 'red')
                        return
                    self.plainTextEdit_unauthorized_data1response.setPlainText('')
                    self.plainTextEdit_unauthorized_data2response.setPlainText('')
                    response1,response2,sum1_dict,sum2_dict = Unauthorized.compare_response(response1,response2)
                    self.plainTextEdit_unauthorized_data1response.appendHtml(response1)
                    self.plainTextEdit_unauthorized_data2response.appendHtml(response2)
                    change_param = Unauthorized.change_param(sum1_dict,sum2_dict)
                    self.print_unauthorized_result('[+] 发现异常值 ' + str(change_param.__len__()) + ' 个', 'red')
                    self.comboBox_unauthorized_selectcharacteristic.clear()
                    self.comboBox_unauthorized_response1value.clear()
                    self.comboBox_unauthorized_response2value.clear()
                    self.comboBox_unauthorized_selectcharacteristic.addItems(change_param)
                    for param in change_param:
                        self.print_unauthorized_result('&nbsp; &nbsp; &nbsp; &nbsp; ' + param, 'red')

                    if response1_body == response2_body:
                        reply = QMessageBox.question(self, '询问', '检测到返回body相同，是否仅检测越权操作？', QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                        if reply == QMessageBox.Yes:
                            self.radioButton_unauthorized_operation.setChecked(True)
                        else:
                            self.print_unauthorized_result('[+] 请自行选择检测模式', 'green')
                else:
                    reply = QMessageBox.question(self, '询问', '数据包参数不相同，仅探查垂直越权？', QMessageBox.Yes | QMessageBox.No,
                                                 QMessageBox.Yes)
                    if reply == QMessageBox.Yes:
                        self.radioButton_unauthorized_vertical.setChecked(True)
                    else:
                        self.print_unauthorized_result('[+] 请自行选择检测模式', 'green')
            except:
                self.print_unauthorized_result('[-] 参数初始化失败', 'red')

        self.pushButton_unauthorized_allparam.clicked.connect(unauthorized_allparam_clicked)

        def change_response_value():
            select = self.comboBox_unauthorized_selectcharacteristic.currentText()
            select_list = select.split(' -> ')
            self.comboBox_unauthorized_response1value.clear()
            self.comboBox_unauthorized_response2value.clear()
            self.comboBox_unauthorized_response1value.addItems(select_list[0].split(','))
            self.comboBox_unauthorized_response2value.addItems(select_list[1].split(','))

        self.comboBox_unauthorized_selectcharacteristic.activated.connect(change_response_value)

        def unauthorized_startallparam_clicked():
            params = {
                'GET':self.lineEdit_unauthorized_getparam.text(),
                'POST':self.lineEdit_unauthorized_postparam.text(),
                'COOKIE':self.lineEdit_unauthorized_cookieparam.text()
            }
            response1_s = self.comboBox_unauthorized_response1value.currentText()
            response2_s = self.comboBox_unauthorized_response2value.currentText()

            try:
                data1request = self.plainTextEdit_unauthorized_data1request.toPlainText().split('\n')
                data2request = self.plainTextEdit_unauthorized_data2request.toPlainText().split('\n')
                request1_dict = Unauthorized.init_request_param(data1request)
                request2_dict = Unauthorized.init_request_param(data2request)
            except:
                self.print_unauthorized_result('[-] 参数初始化失败', 'red')
                return
            if self.radioButton_unauthorized_operation.isChecked():
                isoperation = True
            else:
                isoperation = False
            if self.radioButton_unauthorized_vertical.isChecked():
                isvertical = True
            else:
                isvertical = False
            unauthorized = Unauthorized(request1_dict, request2_dict, params, response1_s, response2_s,isvertical,isoperation)
            unauthorized.str_signal.connect(self.print_unauthorized_result)
            unauthorized.start()
            unauthorized.exec()


        self.pushButton_unauthorized_startallparam.clicked.connect(unauthorized_startallparam_clicked)

        def unauthorized_clearresult_clicked():
            self.plainTextEdit_unauthorized_result.setPlainText('')

        self.pushButton_unauthorized_clearresult.clicked.connect(unauthorized_clearresult_clicked)



        def xss_start_clicked():
            self.plainTextEdit_xss_result.setPlainText('')
            self.plainTextEdit_xss_payload.setPlainText('')
            thread = int(self.comboBox_xss_thread.currentText())
            crawl = self.comboBox_xss_crawl.currentText()
            deep = int(self.comboBox_xss_deep.currentText())
            delay = int(self.comboBox_xss_delay.currentText())
            skipdom = self.comboBox_xss_skipdom.currentText()
            data_request = self.plainTextEdit_xss_request.toPlainText().split('\n')
            if 'http' not in data_request[0]:
                self.print_xss_result('[-] 数据包缺少必要的主机名 (burp数据包应在copy url粘贴在url处,fiddler不需要)','red')
                return
            request_dict = XSS.init_request_param(data_request)
            url = request_dict.url
            post_type = request_dict.post_param_type
            post_data = request_dict.post_param
            old_headers = request_dict.other_header
            cookie = ""
            for key,value in request_dict.cookie.items():
                cookie = cookie + key + '=' + value + ';'
            headers = {
                'cookie':cookie.strip()
            }
            # headers = {}
            # for key,value in old_headers.items():
            #     if 'Connection' in key:
            #         headers['cookie'] = cookie.strip()
            #     headers[key] = value
            if post_type == 'json':
                jsonData = 'y'
            else:
                jsonData = ''
            paramData = str(post_data)
            if paramData == '{}':
                paramData = ''
            if skipdom == '是':
                is_skipdom = True
            else:
                is_skipdom = False
            if crawl == '是':
                is_crawl = True
            else:
                is_crawl = False
            arg = Arg(target=url,jsonData=jsonData,paramData=paramData,level=deep,add_headers=headers,threadCount=thread,delay=delay,skipDOM=is_skipdom,recursive=is_crawl)
            xss = XSS(arg)
            xss.str_signal.connect(self.print_xss_result)
            xss.payload_signal.connect(self.print_xss_payload)
            xss.start()
            xss.exec()


        self.pushButton_xss_start.clicked.connect(xss_start_clicked)

        def xss_wait_clicked():
            plugins.XSStrike.core.config.wait = 1


        self.pushButton_xss_wait.clicked.connect(xss_wait_clicked)

        def shodan_search_clicked():
            #self.tableView_shodan_searchresult.horizontalHeader().setStretchLastSection(True)
            if self.lineEdit_shodan_ip.text() == '':
                self.tableView_shodan_searchresult.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                self.tableView_shodan_searchresult.setSelectionBehavior(QAbstractItemView.SelectRows)
                country = self.comboBox_shodan_city.currentText()
                keyword = self.lineEdit_shodan_keyword.text()
                self.print_shodan_log('查询:' + keyword + '->' + country, 'green')
                key = self.lineEdit_shodan_key.text()
                shodan_handle = Shodan_handle(key,keyword)
                try:
                    total,module = shodan_handle.search(country)
                except:
                    self.print_shodan_log('[-] shodan连接失败','red')
                    return
                self.label_shodan_searchresult.setText('搜索IP结果:' + str(total) + '个')
                # module = QStandardItemModel(6,6)
                # module.setHorizontalHeaderLabels(['IP地址', 'OS', '域名', '端口','地区','详情'])
                # for row in range(6):
                #     for column in range(6):
                #         item = QStandardItem('row %s,column %s' % (row, column))
                #         item.setEditable(False)
                #         module.setItem(row, column, item)
                self.tableView_shodan_searchresult.setModel(module)
            else:
                shodan_searchresult_clicked()

        self.pushButton_shodan_search.clicked.connect(shodan_search_clicked)

        def shodan_searchresult_clicked():
            self.listWidget_shodan_port.clear()
            self.textEdit_shodan_fullinfo.setText('')
            self.plainTextEdit_shodan_hostinfo.setPlainText('')
            if self.lineEdit_shodan_ip.text() == '':
                indexs = self.tableView_shodan_searchresult.selectionModel().selection().indexes()
                ip = self.tableView_shodan_searchresult.model().item(indexs[0].row(),0).text()
            else:
                ip = self.lineEdit_shodan_ip.text()
            self.print_shodan_log('查询ip:' + ip,'green')
            keyword = self.lineEdit_shodan_keyword.text()
            key = self.lineEdit_shodan_key.text()
            shodan_handle = Shodan_handle(key, keyword)
            try:
                ports,host_info,port_info = shodan_handle.query_host(ip)
            except:
                self.print_shodan_log('[-] shodan连接失败', 'red')
                return
            self.print_shodan_hostinfo('Organization:' + host_info['org'],'green')
            self.print_shodan_hostinfo('isp:' + host_info['isp'], 'green')
            self.print_shodan_hostinfo('timestamp:' + host_info['timestamp'], 'green')
            i = 0
            for port in ports:
                self.listWidget_shodan_port.insertItem(i, port)
                try:
                    self.print_shodan_hostinfo(port + ' -> ' + port_info[port], 'red')
                except:
                    pass
                i += 1
        self.tableView_shodan_searchresult.clicked.connect(shodan_searchresult_clicked)

        def shodan_port_clicked(index):
            item = self.listWidget_shodan_port.currentItem()
            port = item.text()
            keyword = self.lineEdit_shodan_keyword.text()
            key = self.lineEdit_shodan_key.text()
            if self.lineEdit_shodan_ip.text() == '':
                indexs = self.tableView_shodan_searchresult.selectionModel().selection().indexes()
                ip = self.tableView_shodan_searchresult.model().item(indexs[0].row(), 0).text()
            else:
                ip = self.lineEdit_shodan_ip.text()
            self.print_shodan_log('查询:' + ip + ':' + port, 'green')
            shodan_handle = Shodan_handle(key, keyword)
            try:
                data = shodan_handle.query_port(ip,port)
            except:
                self.print_shodan_log('[-] shodan连接失败', 'red')
                return
            self.textEdit_shodan_fullinfo.setText(data)

        self.listWidget_shodan_port.clicked.connect(shodan_port_clicked)
        def shodan_clear_clicked():
            self.plainTextEdit_shodan_log.clear()
            self.plainTextEdit_shodan_hostinfo.clear()
            self.listWidget_shodan_port.clear()
            self.tableView_shodan_searchresult.close()

        self.pushButton_shodan_clear.clicked.connect(shodan_clear_clicked)
        def sshusername_start_clicked():
            self.plainTextEdit_sshusername_result.clear()
            ip = self.lineEdit_sshusername_ip.text()
            port = self.lineEdit_sshusername_port.text()
            username = self.lineEdit_sshusername_username.text()
            username_list = self.lineEdit_sshusername_usernamelist.text()
            ssh_username = Ssh_username(ip,port,username,username_list)
            ssh_username.str_signal.connect(self.print_sshusername_result)
            ssh_username.int_signal.connect(self.print_sshusername_progress)
            ssh_username.start()
            ssh_username.exec()

        self.pushButton_sshusername_start.clicked.connect(sshusername_start_clicked)

        def sshusername_stop_clicked():
            if plugins.config.ssh_username_wait == 0:
                plugins.config.ssh_username_wait = 1
                self.pushButton_sshusername_stop.setText('继续')
            else:
                plugins.config.ssh_username_wait = 0
                self.pushButton_sshusername_stop.setText('暂停')

        self.pushButton_sshusername_stop.clicked.connect(sshusername_stop_clicked)

        def sshusername_selectfile_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_sshusername_usernamelist.setText(openfile_name[0])

        self.pushButton_sshusername_selectfile.clicked.connect(sshusername_selectfile_clicked)
        def slowhttp_start_clicked():
            plugins.config.slowhttp_wait = 0
            self.plainTextEdit_slowhttp_result.clear()
            ip = self.lineEdit_slowhttp_ip.text()
            port = self.lineEdit_slowhttp_port.text()
            link_num = self.comboBox_slowhttp_thread.currentText()
            timeout = self.comboBox_slowhttp_time.currentText()
            if ip == '' or port == '':
                reply = QMessageBox.question(self, '错误', 'ip或者port异常', QMessageBox.Yes | QMessageBox.No,
                                             QMessageBox.Yes)
                return
            else:
                slowhttp = Slowhttp(ip,port,link_num,timeout)
                slowhttp.str_signal.connect(self.print_slowhttp_result)
                slowhttp.start()
                slowhttp.exec()

        self.pushButton_slowhttp_start.clicked.connect(slowhttp_start_clicked)
        def slowhttp_stop_clicked():
            plugins.config.slowhttp_wait = 1
            self.plainTextEdit_slowhttp_result.clear()
            self.print_slowhttp_result('[-] 用户取消','red')

        self.pushButton_slowhttp_stop.clicked.connect(slowhttp_stop_clicked)
        def apache_scan_clicked():
            self.plainTextEdit_apache_result.clear()
            url = self.lineEdit_apache_url.text()
            cmd = self.lineEdit_apache_cmd.text()
            cve = self.comboBox_apache_cve.currentText()
            urllist = self.lineEdit_apache_urllist.text()
            apache_cve = ApacheCve(url,urllist,cmd,cve,'scan')
            apache_cve.str_signal.connect(self.print_apache_result)
            apache_cve.start()
            apache_cve.exec()

        self.pushButton_apache_scan.clicked.connect(apache_scan_clicked)

        def apache_exe_clicked():
            self.plainTextEdit_apache_result.clear()
            url = self.lineEdit_apache_url.text()
            cmd = self.lineEdit_apache_cmd.text()
            cve = self.comboBox_apache_cve.currentText()
            urllist = self.lineEdit_apache_urllist.text()
            apache_cve = ApacheCve(url,urllist, cmd, cve, 'exe')
            apache_cve.str_signal.connect(self.print_apache_result)
            apache_cve.start()
            apache_cve.exec()
        self.pushButton_apache_exe.clicked.connect(apache_exe_clicked)
        def apache_selectfile_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_apache_urllist.setText(openfile_name[0])

        self.pushButton_apache_selectfile.clicked.connect(apache_selectfile_clicked)

        def jboss_urllist_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_jboss_urllist.setText(openfile_name[0])

        self.pushButton_jboss_urllist.clicked.connect(jboss_urllist_clicked)

        def jboss_ysoserialpath_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.jar)')
            self.lineEdit_jboss_jar.setText(openfile_name[0])
        self.pushButton_jboss_ysoserialpath.clicked.connect(jboss_ysoserialpath_clicked)


        def jboss_scan_clicked():
            ysoserialpath = self.lineEdit_jboss_jar.text()
            urllist = self.lineEdit_jboss_urllist.text()
            url = self.lineEdit_jboss_url.text()
            if ysoserialpath == "":
                self.print_jboss_result("[-] 未找到ysoserial 路径..",'red')
                return
            jboss = Jboss(active="scan",ysoserial_path=ysoserialpath,url_list=urllist,url=url)
            jboss.str_signal.connect(self.print_jboss_result)
            jboss.start()
            jboss.exec()
            jboss.destroyed()

        self.pushButton_jboss_scan.clicked.connect(jboss_scan_clicked)


        def jboss_clearlog_clicked():
            self.plainTextEdit_jboss_result.setPlainText("")

        self.pushButton_jboss_clearlog.clicked.connect(jboss_clearlog_clicked)

        def sqlmap_disolay_taskid(taskid:str):
            self.label_sqlmap_taskid.setText("当前taskid:" + taskid)

        def jboss_exe_clicked():
            ysoserialpath = self.lineEdit_jboss_jar.text()
            url = self.lineEdit_jboss_url.text()
            if url == "":
                self.print_jboss_result("[-] url不存在..", 'red')
                return
            cmd = self.lineEdit_jboss_cmd.text()
            select_bug = self.comboBox_jboss_cve.currentText()
            jboss = Jboss(active='execmd',ysoserial_path=ysoserialpath,url=url,cmd=cmd,select_bug=select_bug)
            jboss.str_signal.connect(self.print_jboss_result)
            jboss.start()
            jboss.exec()
            jboss.destroyed()


        self.pushButton_jboss_exe.clicked.connect(jboss_exe_clicked)

        def sqlmap_checkenv_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, active="checkenv", data={})
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.pushButton_sqlmap_checkenv.clicked.connect(sqlmap_checkenv_clicked)

        def sqlmap_selectfile_clicked():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_sqlmap_filepath.setText(openfile_name[0])

        self.pushButton_sqlmap_selectfile.clicked.connect(sqlmap_selectfile_clicked)

        def sqlmap_clearlog_clicked():
            pass

        self.pushButton_sqlmap_clearlog.clicked.connect(sqlmap_clearlog_clicked)

        def sqlmap_display_dbs(dbs: list):
            self.listWidget_sqlmap_dbs.clear()
            dbs.sort()
            try:
                i = 0
                for db in dbs:
                    self.listWidget_sqlmap_dbs.insertItem(i, db)
                    i += 1
            except:
                self.print_sqlmap_result("[-] 操作频繁，请再试一次...",'red')
            return

        def sqlmap_startscan_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            select_file_path = self.lineEdit_sqlmap_filepath.text()
            data = {
                'requestFile': select_file_path
            }
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, active="scan", data=data)
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.sysinfo_signal.connect(self.print_sqlmap_sysinfo)
            sqlmap.dbs_signal.connect(sqlmap_display_dbs)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.pushButton_sqlmap_startscan.clicked.connect(sqlmap_startscan_clicked)

        def sqlmap_display_table(tables: list):
            self.listWidget_sqlmap_tables.clear()
            tables.sort()
            i = 0
            for table in tables:
                self.listWidget_sqlmap_tables.insertItem(i, table)
                i += 1
            return

        def sqlmap_dbs_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            db_name = self.listWidget_sqlmap_dbs.currentItem().text()
            select_file_path = self.lineEdit_sqlmap_filepath.text()
            data = {
                'requestFile': select_file_path,
                'db': db_name,
                'getTables': True
            }
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, data=data, active="get_tables")
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.table_signal.connect(sqlmap_display_table)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.listWidget_sqlmap_dbs.clicked.connect(sqlmap_dbs_clicked)

        def sqlmap_display_column(columns: list):
            self.listWidget_sqlmap_columns.clear()
            columns.sort()
            i = 0
            for column in columns:
                self.listWidget_sqlmap_columns.insertItem(i, column)
                i += 1
            return

        def sqlmap_tables_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            db_name = self.listWidget_sqlmap_dbs.currentItem().text()
            table_name = self.listWidget_sqlmap_tables.currentItem().text()
            select_file_path = self.lineEdit_sqlmap_filepath.text()
            data = {
                'requestFile': select_file_path,
                'db': db_name,
                'tbl': table_name,
                'getColumns': True
            }
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, data=data, active="get_columns")
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.column_signal.connect(sqlmap_display_column)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.listWidget_sqlmap_tables.clicked.connect(sqlmap_tables_clicked)

        def sqlmap_display_query_result(module: QStandardItemModel):
            self.tableView_sqlmap_query.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.tableView_sqlmap_query.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.tableView_sqlmap_query.setModel(module)

        def sqlmap_change_button_status(status:str):
            if status == "off":
                self.pushButton_sqlmap_exesql.setText("执行中")
                self.pushButton_sqlmap_exesql.setEnabled(False)
            else:
                self.pushButton_sqlmap_exesql.setText("Go!")
                self.pushButton_sqlmap_exesql.setEnabled(True)

        def sqlmap_exesql_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            select_file_path = self.lineEdit_sqlmap_filepath.text()
            sql = self.lineEdit_sqlmap_sqlshell.text()
            data = {
                'requestFile': select_file_path,
                'sqlQuery': sql
            }
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, data=data, active="sql_shell")
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.query_result_signal.connect(sqlmap_display_query_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.change_exesql_status.connect(sqlmap_change_button_status)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.pushButton_sqlmap_exesql.clicked.connect(sqlmap_exesql_clicked)

        def sqlmap_clearlog_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, data={}, active="flush_task")
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.change_exesql_status.connect(sqlmap_change_button_status)
            sqlmap.start()
            self.tableView_sqlmap_query.setModel(QStandardItemModel())
            self.plainTextEdit_sqlmap_result.setPlainText("")
            self.plainTextEdit_sqlmap_sysinfo.clear()
            self.listWidget_sqlmap_columns.clear()
            self.listWidget_sqlmap_tables.clear()
            self.listWidget_sqlmap_dbs.clear()
            sqlmap.exec()
            sqlmap.destroyed()

        self.pushButton_sqlmap_clearlog.clicked.connect(sqlmap_clearlog_clicked)

        def sqlmap_kill_clicked():
            sqlmapapi_url = self.lineEdit_sqlmap_apiurl.text()
            taskid = self.label_sqlmap_taskid.text().split(':')[-1]
            data = {
                'taskid':taskid
            }
            sqlmap = Use_sqlmap(sqlmapapi_url=sqlmapapi_url, data=data, active="task_kill")
            sqlmap.str_signal.connect(self.print_sqlmap_result)
            sqlmap.update_taskid_signal.connect(sqlmap_disolay_taskid)
            sqlmap.start()
            sqlmap.exec()
            sqlmap.destroyed()

        self.pushButton_sqlmap_kill.clicked.connect(sqlmap_kill_clicked)

        def windows_exe_clicked():
            ip = self.lineEdit_windows_ip.text()
            port = self.lineEdit_windows_port.text()
            if ip == "":
                self.print_windows_result("[-] 没有输入ip地址 ",'red')
                return
            cmd = self.lineEdit_windows_cmd.text()
            select_bug = self.comboBox_windows_comboBox.currentText()
            windows= Windows(ip=ip,port=port,cmd=cmd,select_bug=select_bug,active="exe")
            windows.str_signal.connect(self.print_windows_result)
            windows.start()
            windows.exec()
            windows.destroyed()


        self.pushButton_windows_exe.clicked.connect(windows_exe_clicked)


        def windows_scan_clicked():
            ip = self.lineEdit_windows_ip.text()
            port = self.lineEdit_windows_port.text()
            if ip == "":
                self.print_windows_result("[-] 没有输入ip地址 ",'red')
                return
            cmd = self.lineEdit_windows_cmd.text()
            select_bug = self.comboBox_windows_comboBox.currentText()
            windows= Windows(ip=ip,port=port,cmd=cmd,select_bug=select_bug,active="scan")
            windows.str_signal.connect(self.print_windows_result)
            windows.start()
            windows.exec()
            windows.destroyed()


        self.pushButton_windows_scan.clicked.connect(windows_scan_clicked)

        def tomcat_2020_1938_select_file():
            openfile_name = QFileDialog.getOpenFileName(self, '选择文件', '', 'Excel files(*.txt)')
            self.lineEdit_tomcat_2020_1938_ip_list.setText(openfile_name[0])

        self.pushButton_tomcat_2020_1938_select_file.clicked.connect(tomcat_2020_1938_select_file)


        def tomcat_2020_1938_check_clicked():
            self.plainTextEdit_tomcat_2020_1938_result.setPlainText("")
            self.print_tomcat_2020_1938_result("[+] 开始进行漏洞检测...", 'green')
            ip = self.lineEdit_tomcat_2020_1938_ip.text()
            ip_list = self.lineEdit_tomcat_2020_1938_ip_list.text()
            try:
                port = int(self.lineEdit_tomcat_2020_1938_port.text())
            except:
                self.print_tomcat_2020_1938_result("[-] 请输入正确的端口",'red')
                return
            if ip != "":
                tomcat = Tomcat_("CVE-2020-1938",ip,'',port,'check')
            else:
                tomcat = Tomcat_("CVE-2020-1938", '', ip_list, port, 'check')
            tomcat.str_signal.connect(self.print_tomcat_2020_1938_result)
            tomcat.start()
            tomcat.exec()
            tomcat.destroyed()

        self.pushButton_tomcat_2020_1938_check.clicked.connect(tomcat_2020_1938_check_clicked)

        def tomcat_2020_1938_read_file_clicked():
            self.plainTextEdit_tomcat_2020_1938_result.setPlainText("")
            self.print_tomcat_2020_1938_result("[+] 开始进行文件读取...", 'green')
            read_file = self.lineEdit_tomcat_2020_1938_file_path.text()
            ip = self.lineEdit_tomcat_2020_1938_ip.text()
            if ip == "":
                self.print_tomcat_2020_1938_result("[-] ip是必须的", 'red')
                return
            try:
                port = int(self.lineEdit_tomcat_2020_1938_port.text())
            except:
                self.print_tomcat_2020_1938_result("[-] 请输入正确的端口",'red')
                return
            tomcat = Tomcat_("CVE-2020-1938", ip, '', port, 'read_file',file=read_file)
            tomcat.str_signal.connect(self.print_tomcat_2020_1938_result)
            tomcat.start()
            tomcat.exec()
            tomcat.destroyed()


        self.pushButton_tomcat_2020_1938_read_file.clicked.connect(tomcat_2020_1938_read_file_clicked)







if __name__ == '__main__':
    app = QApplication(sys.argv)
    myWin = MyWindow()
    myWin.setWindowTitle("漏洞利用工具集 Gr33k 仅供技术交流 若用于非法途径，概不负责")
    myWin.setWindowIcon(QIcon('icon/title.png'))
    myWin.show()
    sys.exit(app.exec_())
