from PyQt5.Qt import QThread,pyqtSignal
import re
from urllib.parse import urlparse,parse_qsl
import requests
import json
import difflib
import copy

class Request_dict():
    post_param = {}
    post_param_type = ''
    get_param = {}
    other_header = {}
    method = ''
    cookie = {}
    url = ''

    def __init__(self):
        self.post_param = {}
        self.post_param_type = ''
        self.get_param = {}
        self.other_header = {}
        self.method = ''
        self.cookie = {}
        self.url = ''


class Unauthorized(QThread):

    str_signal = pyqtSignal([str,str])

    def __init__(self,request1_dict,request2_dict,params,response1_s,response2_s,isvertical,isoperation):
        super().__init__()
        self.request1_dict = request1_dict
        self.request2_dict = request2_dict
        self.params = params
        self.response1_s = response1_s
        self.response2_s = response2_s
        self.isvertical = isvertical
        self.isoperation = isoperation

    @staticmethod
    def init_request_param(data1request:list):
        request_dict = Request_dict()
        request_dict.method = data1request[0].split(' ')[0].strip()
        for line in data1request[:-1]:
            if 'HTTP' in line:
                request_dict.url = line.split(' ')[1].strip()
            elif re.findall('cookie',line,flags=re.IGNORECASE):
                for cookie in line.split(':')[1].split(';'):
                    request_dict.cookie[cookie.split('=')[0]] = cookie.replace(cookie.split('=')[0] + '=','').strip()
            elif line == '':
                pass
            else:
                request_dict.other_header[line.split(':')[0]] = line.split(':')[1].strip()
        if request_dict.method == "POST":
            #还要处理当post数据为json时的情况
            try:
                post_data = json.loads(data1request[-1])
                for key in post_data.keys():
                    request_dict.post_param[key] = post_data[key]
                request_dict.post_param_type = 'json'
            except:
                for post_param in data1request[-1].split('&'):
                    request_dict.post_param[post_param.split('=')[0]] = post_param.split('=')[1].strip()
                request_dict.post_param_type = 'str'
        elif request_dict.method == 'GET':
            get_params = parse_qsl(urlparse(request_dict.url).query)
            for get_param in get_params:
                request_dict.get_param[get_param[0]] = get_param[1].strip()
        return request_dict

    @staticmethod
    def get_params_name(request_dict:Request_dict):
        cookie = ''
        get_param = ''
        post_param = ''
        for cookie_name in request_dict.cookie.keys():
            cookie += cookie_name + ','
        for get_name in request_dict.get_param.keys():
            get_param += get_name + ','
        for post_name in request_dict.post_param.keys():
            post_param += post_name + ','
        return get_param,post_param,cookie

    @staticmethod
    def add_dict(old_dict: dict, new_dict: dict):
        return_dict = {}
        for key in list(new_dict.keys()):
            a = new_dict[key]
            if key in list(old_dict.keys()):
                return_dict[key] = list(old_dict[key]) + list(new_dict[key])
                del new_dict[key]
                del old_dict[key]
        return_dict.update(old_dict)
        return_dict.update(new_dict)
        return return_dict

    @staticmethod
    def create_request(request_dict:Request_dict):
        header = {}
        data = {}
        str_cookie = ''
        for cookie_name in request_dict.cookie.keys():
            str_cookie += cookie_name + '=' + request_dict.cookie[cookie_name].strip() + ';'
        header['cookie'] = str_cookie.strip()
        for head in request_dict.other_header.keys():
            header[head] = request_dict.other_header[head]
        url_result = urlparse(request_dict.url)
        get_params = ''
        for param in request_dict.get_param.keys():
            get_params += param + request_dict.get_param[param] + '&'
        url = url_result[0] + '://' + url_result[1] + url_result[2] + '?' + get_params[0:-1]
        if request_dict.method == 'POST':
            data = request_dict.post_param
        return url,header,data

    @staticmethod
    def compare_response(response1,response2):
        res1 = response1.splitlines()
        res2 = response2.splitlines()
        d = difflib.HtmlDiff()
        html = d.make_file(res1, res2)
        with open('diff.html', mode='w', encoding='utf-8') as f:
            f.write(html)

        change1_str = {}
        add1_str = {}
        sub1_str = {}
        change2_str = {}
        add2_str = {}
        sub2_str = {}
        html = open('diff.html', 'r').read()
        p = re.compile(r'<a href="#difflib_(.*?)<td class="diff_header" id="from(.*?)_(.*?)">(.*?)</td>(.*?)<td class="diff_header"(.*?)</tr>')
        for m in p.finditer(html):
            change1_list = []
            add1_list = []
            sub1_list = []
            change2_list = []
            add2_list = []
            sub2_list = []
            line_num = m.group(4)
            data1_read_line = m.group(5)
            data2_read_line = m.group(6)
            change_p = re.compile(r'<span class="diff_chg">([\s\S]*?)</span>')
            add_p = re.compile(r'<span class="diff_add">([\s\S]*?)</span>')
            sub_p = re.compile(r'<span class="diff_sub">([\s\S]*?)</span>')
            for m in change_p.finditer(data1_read_line):
                s = m.group(1)
                change1_list.append(s)
            change1_str[line_num] = change1_list
            for m in add_p.finditer(data1_read_line):
                s = m.group(1)
                add1_list.append(s)
            add1_str[line_num] = add1_list
            for m in sub_p.finditer(data1_read_line):
                s = m.group(1)
                sub1_list.append(s)
            sub1_str[line_num] = sub1_list


            for m in change_p.finditer(data2_read_line):
                s = m.group(1)
                change2_list.append(s)
            change2_str[line_num] = change2_list
            for m in add_p.finditer(data2_read_line):
                s = m.group(1)
                add2_list.append(s)
            add2_str[line_num] = add2_list
            for m in sub_p.finditer(data2_read_line):
                s = m.group(1)
                sub2_list.append(s)
            sub2_str[line_num] = sub2_list



        sum1_dict = {}
        sum1_dict = Unauthorized.add_dict(sum1_dict, change1_str)
        sum1_dict = Unauthorized.add_dict(sum1_dict, add1_str)
        sum1_dict = Unauthorized.add_dict(sum1_dict, sub1_str)

        if sum1_dict['1'].__len__() == 0:
            del sum1_dict['1']


        sum2_dict = {}
        sum2_dict = Unauthorized.add_dict(sum2_dict, change2_str)
        sum2_dict = Unauthorized.add_dict(sum2_dict, add2_str)
        sum2_dict = Unauthorized.add_dict(sum2_dict, sub2_str)

        if sum2_dict['1'].__len__() == 0:
            del sum2_dict['1']



        with open('data1response.txt','w',encoding='utf-8') as f:
            f.write(response1)
        with open('data2response.txt','w',encoding='utf-8') as f:
            f.write(response2)

        response1 = Unauthorized.create_return_response('data1response.txt',sum1_dict)
        response2 = Unauthorized.create_return_response('data2response.txt', sum2_dict)

        response1 = Unauthorized.replace_str(response1)
        response2 = Unauthorized.replace_str(response2)

        return response1,response2,sum1_dict,sum2_dict

    @staticmethod
    def get_change(html):
        pass

    @staticmethod
    def create_return_response(file_path:str,sum_dict:dict):
        with open(file_path, 'r') as f:
            data_response_content = ''
            line_num = 1
            for line in f.readlines():
                if str(line_num) in sum_dict.keys():
                    for change_string in sum_dict[str(line_num)]:
                        line = line.replace(change_string, '~~~l' + change_string + '~~~r')
                    data_response_content += line
                else:
                    data_response_content += line
                line_num += 1
            return data_response_content

    @staticmethod
    def replace_str(response):
        response = response.replace("&","&amp;")
        response = response.replace(">","&gt;")
        response = response.replace("<","&lt;")
        response = response.replace("\"","&quot;")
        response = response.replace("\'","&#39;")
        response = response.replace(" ","&nbsp;")
        response = response.replace("\n","<br>")
        response = response.replace('~~~l', '<span style="color:yellow">')
        response = response.replace('~~~r', '</span>')
        return response




    @staticmethod
    def send_query(request_dict:Request_dict):
        url,header,data = Unauthorized.create_request(request_dict)
        if request_dict.method == "GET":
            res = requests.get(url=url,headers=header)
            res.encoding = 'utf8'
            response = str(res.status_code) + '\n'
            for head in res.headers.keys():
                response += head + ':' + res.headers[head] + '\n'
            response += '\n\n' + res.text
            response_body = res.text
        elif request_dict.method == "POST":
            if request_dict.post_param_type == 'json':
                data = json.dumps(data)
                res = requests.post(url=url,headers=header,data=data)
            else:
                res = requests.post(url=url, headers=header, data=data)
            response = str(res.status_code) + '\n'
            for head in res.headers.keys():
                response += head + ':' + res.headers[head] + '\n'
            response += '\n\n' + res.text
            response_body = res.text
        else:
            response = '[-] 仅支持GET 与 POST 请求'
            response_body = str(request_dict)
        return response,response_body

    @staticmethod
    def change_param(sum1_dict:dict,sum2_dict:dict):
        param_list = []
        for line_num in sum1_dict.keys():
            s = ''
            s1 = ''
            for m in sum1_dict[line_num]:
                s += m + ','
            for m in sum2_dict[line_num]:
                s1 += m + ','
            s = s + ' -> ' + s1
            param_list.append(s)
        return set(param_list)


    @staticmethod
    def query_param_exit(response,param):
        if param in response:
            return True,param
        else:
            return False,None

    @staticmethod
    def changeall_request_dict(params:dict,data1request_dict:Request_dict,data2request_dict:Request_dict):
        get_list = params['GET'].split(',')
        post_list = params['POST'].split(',')
        cookie_list = params['COOKIE'].split(',')
        for param in get_list:
            data1request_dict.get_param[param] = data2request_dict.get_param[param]
        for param in post_list:
            data1request_dict.post_param[param] = data2request_dict.post_param[param]
        for param in cookie_list:
            data1request_dict.cookie[param] = data2request_dict.cookie[param]
        return data1request_dict

    def scan_param(self,params:dict,data1request_dict:Request_dict,data2request_dict:Request_dict,response1_s:str,response2_s:str):
        params['GET'] = [i for i in params['GET'].split(',') if i != '']
        params['POST'] = [i for i in params['POST'].split(',') if i != '']
        params['COOKIE'] = [i for i in params['COOKIE'].split(',') if i != '']
        for key in params.keys():
            for param in params[key]:
                if param in data1request_dict.get_param.keys():
                    if data1request_dict.get_param[param] != data2request_dict.get_param[param]:
                        self.str_signal[str, str].emit('[+] 正在探测 GET参数 ->' + param, 'green')
                        data1request_dict.get_param[param] = data2request_dict.get_param[param]
                    else:
                        self.str_signal[str, str].emit('[+]  GET参数 -> ' + param + ' 值相同，跳过检测', 'green')
                        continue
                elif param in data1request_dict.post_param.keys():
                    if data1request_dict.post_param[param] != data2request_dict.post_param[param]:
                        self.str_signal[str, str].emit('[+] 正在探测 POST参数 ->' + param, 'green')
                        data1request_dict.post_param[param] = data2request_dict.post_param[param]
                    else:
                        self.str_signal[str, str].emit('[+]  POST参数 -> ' + param + ' 值相同，跳过检测', 'green')
                        continue
                elif param in data1request_dict.cookie.keys():
                    if data1request_dict.cookie[param] != data2request_dict.cookie[param]:
                        self.str_signal[str, str].emit('[+] 正在探测 COOKIE参数 ->' + param, 'green')
                        data1request_dict.cookie[param] = data2request_dict.cookie[param]
                    else:
                        self.str_signal[str, str].emit('[+]  COOKIE参数 -> ' + param + ' 值相同，跳过检测', 'green')
                        continue
                else:
                    self.str_signal[str, str].emit('[+] 参数未在数据包中找到...', 'red')
                    continue
                response, response_body = Unauthorized.send_query(data1request_dict)
                is_vuln,param_s = Unauthorized.query_param_exit(response,response2_s)
                if is_vuln:
                    self.str_signal[str, str].emit('[+] 参数 ->' + param + ' 存在越权漏洞,在响应中发现 request2 参数回显：' + param_s, 'red')
                else:
                    self.str_signal[str, str].emit('[+] 参数 ->' + param + ' 不存在越权漏洞', 'green')



    def vertical(self,request1_dict:Request_dict,request2_dict:Request_dict):
        #url不同时,包格式不同时
        self.str_signal[str, str].emit('[+] 正在探测-垂直越权...', 'green')
        data2response, data2_body = Unauthorized.send_query(request2_dict)
        request2_dict.cookie = request1_dict.cookie
        new_data2response,new_data2_body = Unauthorized.send_query(request2_dict)
        similar = Unauthorized.string_similar(data2_body,new_data2_body)
        if similar > 0.95:
            self.str_signal[str,str].emit('[+] 相似度: ' + str(similar) + ' 判断存在垂直越权，使用request1 cookie 发送request2请求成功','red')
        else:
            self.str_signal[str, str].emit('[-] 相似度: ' + str(similar) + ' 判断不存在垂直越权，使用request1 cookie 发送request2请求失败', 'green')
        return request2_dict,new_data2response

    def operation(self,request1_dict:Request_dict,request2_dict:Request_dict):
        #当回包相同时
        self.str_signal[str, str].emit('[+] 正在探测-越权操作...', 'green')
        data2response, data2_body = Unauthorized.send_query(request2_dict)
        request2_dict.cookie = request1_dict.cookie
        new_data2response, new_data2_body = Unauthorized.send_query(request2_dict)
        if data2_body == new_data2_body:
            self.str_signal[str, str].emit('[+]  判断存在越权操作，使用request1 cookie 发送request2请求成功', 'red')
            self.str_signal[str, str].emit('[+]  开始测试参数，执行替换参数代码...', 'green')
            #替换各个参数，查看返回是否成功
            get_params,post_params,cookie = Unauthorized.get_params_name(request1_dict)
            for param in [i for i in get_params.split(',') if i != ''] :
                if request1_dict.get_param[param] != request2_dict.get_param[param]:
                    request1_dict.get_param[param] = request2_dict.get_param[param]
                    response, response_body = Unauthorized.send_query(request1_dict)
                    if response_body == data2_body:
                        self.str_signal[str, str].emit('[+]  GET参数 -> ' + param + ' 可能存在越权漏洞 -> 漏洞类型：越权操作', 'red')
                else:
                    self.str_signal[str, str].emit('[+]  GET参数 -> ' + param + ' 值相同，跳过检测', 'green')
            for param in [i for i in post_params.split(',') if i != '']:
                if request1_dict.post_param[param] != request2_dict.post_param[param]:
                    request1_dict.post_param[param] = request2_dict.post_param[param]
                    response, response_body = Unauthorized.send_query(request1_dict)
                    if response_body == data2_body:
                        self.str_signal[str, str].emit('[+]  POST参数 -> ' + param + ' 可能存在越权漏洞 -> 漏洞类型：越权操作', 'red')
                else:
                    self.str_signal[str, str].emit('[+]  POST参数 -> ' + param + ' 值相同，跳过检测', 'green')
        else:
            self.str_signal[str, str].emit('[+]  判断不存在垂直越权，使用request1 cookie 发送request2请求回应不相同', 'green')
        return request2_dict, new_data2response


    def run(self):
        self.str_signal[str, str].emit('[+] ================开始执行================', 'green')
        if self.isvertical:
            try:
                self.vertical(copy.deepcopy(self.request1_dict),copy.deepcopy(self.request2_dict))
            except:
                self.str_signal[str,str].emit('[-] 垂直越权探测失败', 'red')
        if self.isoperation:
            try:
                self.operation(copy.deepcopy(self.request1_dict), copy.deepcopy(self.request2_dict))
            except:
                self.str_signal[str, str].emit('[-] 越权操作探测失败', 'red')
        try:
            self.scan_param(copy.deepcopy(self.params), copy.deepcopy(self.request1_dict), copy.deepcopy(self.request2_dict), copy.deepcopy(self.response1_s), copy.deepcopy(self.response2_s))
        except:
            self.str_signal[str, str].emit('[-] 参数扫描失败', 'red')
        self.str_signal[str, str].emit('[+] ================执行完毕================', 'green')








    @staticmethod
    def string_similar(s1,s2):
        return difflib.SequenceMatcher(None, s1, s2).quick_ratio()
