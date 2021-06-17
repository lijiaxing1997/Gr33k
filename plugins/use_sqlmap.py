from PyQt5.Qt import pyqtSignal,QThread
import requests
import time
import json
import subprocess
import os
from PyQt5.QtGui import QStandardItemModel,QStandardItem

class Use_sqlmap(QThread):
    str_signal = pyqtSignal([str,str])
    sysinfo_signal = pyqtSignal([str, str])
    dbs_signal = pyqtSignal([list])
    table_signal = pyqtSignal([list])
    column_signal = pyqtSignal([list])
    query_result_signal = pyqtSignal([QStandardItemModel])
    update_taskid_signal = pyqtSignal([str])
    change_exesql_status = pyqtSignal([str])

    sqlmapapi_url = ""
    active = ""
    headers = {
        'Content-Type':'application/json'
    }
    data = {}
    log = []
    task_id = ""

    def __init__(self,sqlmapapi_url,active,data):
        super().__init__()
        if sqlmapapi_url[-1] == '/':
            sqlmapapi_url = sqlmapapi_url[:-1]
        self.sqlmapapi_url = sqlmapapi_url
        print(self.sqlmapapi_url)
        self.active = active
        self.data = data

    def create_task(self):
        url = self.sqlmapapi_url + "/task/new"
        try:
            new_task = requests.get(url=url,timeout=5)
            if new_task.json()['success'] == True:
                taskid = new_task.json()['taskid']
                self.update_taskid_signal[str].emit(str(taskid))
                self.str_signal[str,str].emit("[+] 新任务开启成功 taskid=" + taskid,'green')
                return taskid
            else:
                self.str_signal[str, str].emit("[-] 任务创建失败", 'red')
                return False
        except:
            self.str_signal[str, str].emit("[-] 连接超时", 'red')
            return False

    def task_status(self):
        url = self.sqlmapapi_url + '/scan/' + str(self.task_id) + '/status'
        status = requests.get(url=url,timeout=5)
        return status.json()

    def task_kill(self):
        self.task_id = self.data['taskid']
        if self.task_id == "" or self.task_id == "null":
            self.str_signal[str, str].emit("[+] 没有任务在执行...", 'green')
            return
        url = self.sqlmapapi_url + '/scan/' + str(self.task_id) + '/kill'
        try:
            status = requests.get(url=url, timeout=5)
        except:
            self.str_signal[str, str].emit("[-] sqlmapapi连接失败", 'red')
            return
        if status.json()['success'] == True:
            self.str_signal[str, str].emit("[+] 任务终止成功", 'green')
            self.update_taskid_signal.emit("null")
        else:
            self.str_signal[str, str].emit("[-] 任务终止失败", 'red')

    def start_task(self,data):
        url = self.sqlmapapi_url + "/scan/" + str(self.task_id) + "/start"
        task = requests.post(url=url, data=json.dumps(data),
                             headers=self.headers,timeout=5)
        return task.json()

    def data_task(self):
        url =self.sqlmapapi_url + "/scan/" + str(self.task_id) + "/data"
        result = requests.get(url=url,timeout=5)
        return result.json()

    def log_task(self):
        url = self.sqlmapapi_url + "/scan/" + str(self.task_id) + "/log"
        result = requests.get(url=url, timeout=5)
        return result.json()

    def flush_task(self):
        url = self.sqlmapapi_url + "/admin/flush"
        try:
            result = requests.get(url=url, timeout=5)
            self.str_signal[str, str].emit("[+] 任务清除成功 ", 'green')
            self.update_taskid_signal[str].emit("null")
            self.change_exesql_status[str].emit("on")
        except:
            self.str_signal[str, str].emit("[+] 任务清除失败 ", 'red')
        time.sleep(1)



    def checkenv(self):
        self.str_signal[str, str].emit("[+] 准备测试sqlmap api接口是否准备完毕 ",'green')
        self.str_signal[str, str].emit("[+] 进行新建注入任务测试... ", 'green')
        self.task_id = self.create_task()
        if self.task_id != False:
            self.str_signal[str, str].emit("[+] 测试成功，您可以正常使用 ", 'green')
            return
        else:
            self.str_signal[str, str].emit("[-] 连接sqlmap api失败，请检查sqlmap api状态", 'red')
            return

    def print_log(self,log:dict):
        change_log = []
        for line in log['log']:
            if line not in self.log['log']:
                change_log.append(line)
        for line_log in change_log:
            self.str_signal[str, str].emit("[+] ["+ line_log['time'] +"] [" + line_log['level'] + '] ' + line_log['message'], 'green')
        self.log = log

    def analyse_scan_result_data(self,data):
        self.sysinfo_signal[str,str].emit("数据库类型: " + str(data['data'][1]['value'][0]['dbms']),'red')
        self.sysinfo_signal[str, str].emit("数据库版本: " + str(data['data'][1]['value'][0]['dbms_version']),'red')
        self.sysinfo_signal[str, str].emit("操作系类型: " + str(data['data'][1]['value'][0]['os']),'red')

    def get_dbs(self):
        data = self.data
        data['getDbs'] = True
        result = self.start_task(data=data)
        if result['success'] == True:
            self.show_log()
            result_data = self.data_task()
            if result_data['data'][2]['status'] == 1:
                dbs = result_data['data'][2]['value']
                self.dbs_signal[list].emit(dbs)
            else:
                self.dbs_signal[list].emit([])



    def scan_injection(self):
        self.task_id = self.create_task()
        if self.task_id == False:
            self.str_signal[str, str].emit("[-] 扫描启动失败 ", 'red')
            return
        task = self.start_task(data=self.data)
        if task['success'] == True:
            self.str_signal[str, str].emit("[+] task_id : " + str(self.task_id) + " 扫描开始 ", 'green')
        else:
            self.str_signal[str, str].emit("[-] task_id : " + str(self.task_id) + " 扫描启动失败 ", 'red')
            return
        self.show_log()
        result_data = self.data_task()
        if result_data['data'] != []:
            self.str_signal[str, str].emit("[+] task_id : " + str(self.task_id) + " 存在注入! ", 'red')
            self.analyse_scan_result_data(result_data)
            self.get_dbs()
        else:
            self.str_signal[str, str].emit("[+] task_id : " + str(self.task_id) + " 没有发现注入 ", 'green')

    def show_log(self):
        while True:
            status = self.task_status()
            if status['status'] == "running":
                log = self.log_task()
                self.print_log(log)
            else:
                break
            time.sleep(1)

    def get_tables(self):
        self.task_id = self.create_task()
        if self.task_id == False:
            self.str_signal[str, str].emit("[-] 任务启动失败 ", 'red')
            return
        try:
            task = self.start_task(data=self.data)
            self.show_log()
        except:
            self.str_signal[str, str].emit("[-] 任务执行出错 ", 'red')
            return
        try:
            result_data = self.data_task()
            tables = result_data['data'][2]['value'][self.data['db']]
            self.table_signal[list].emit(tables)
        except:
            self.str_signal[str, str].emit("[-] 任务执行出错 ", 'red')

    def get_columns(self):
        self.task_id = self.create_task()
        if self.task_id == False:
            self.str_signal[str, str].emit("[-] 任务启动失败 ", 'red')
            return
        try:
            task = self.start_task(data=self.data)
            self.show_log()
        except:
            self.str_signal[str, str].emit("[-] 任务执行出错 ", 'red')
            return
        result_data = self.data_task()
        columns = list(result_data['data'][2]['value'][self.data['db']][self.data['tbl']].keys())
        self.column_signal[list].emit(columns)

    def sql_shell(self):
        self.change_exesql_status[str].emit("off")
        self.task_id = self.create_task()
        if self.task_id == False:
            self.str_signal[str, str].emit("[-] 任务启动失败 ", 'red')
            self.change_exesql_status[str].emit("on")
            return
        try:
            task = self.start_task(data=self.data)
            self.show_log()
        except:
            self.str_signal[str, str].emit("[-] 任务执行出错 ", 'red')
            self.change_exesql_status[str].emit("on")
            return
        try:
            result_data = self.data_task()
            result_data = list(result_data['data'][2]['value'])
        except:
            self.str_signal[str, str].emit("[-] 任务执行出错 ", 'red')
            self.change_exesql_status[str].emit("on")
            return
        try:
            try:
                rows = result_data.__len__()
                cols = result_data[0].__len__()
            except:
                self.str_signal[str, str].emit("[-] 未查询到结果 ", 'red')
                self.change_exesql_status[str].emit("on")
                return
            self.str_signal[str,str].emit("[+] 共查询出结果 " + str(rows) + " 条", 'green')
            module = QStandardItemModel(rows, cols)
            for row in range(rows):
                self.str_signal[str, str].emit("[+] 整理第 " + str(row + 1) + " 条记录", 'green')
                for col in range(cols):
                    item = QStandardItem(str(result_data[row][col]))
                    module.setItem(row,col,item)
            self.query_result_signal[QStandardItemModel].emit(module)
        except:
            self.str_signal[str, str].emit("[-] 查询出错", 'red')
            self.change_exesql_status[str].emit("on")
            return
        time.sleep(5)
        self.change_exesql_status[str].emit("on")
        self.str_signal[str, str].emit("[+] 查询结束 ", 'green')




    def run(self):
        if self.active == 'checkenv':
            self.checkenv()
        elif self.active == "scan":
            self.scan_injection()
        elif self.active == "get_tables":
            self.get_tables()
        elif self.active == "get_columns":
            self.get_columns()
        elif self.active == "sql_shell":
            self.sql_shell()
        elif self.active == "flush_task":
            self.flush_task()
        elif self.active == "task_kill":
            self.task_kill()