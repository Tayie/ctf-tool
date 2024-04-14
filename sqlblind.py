import requests
import sys
import getopt
import json
import blind

def main():
    global url
    global base # the base method
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hu:b:", ["help", "GET", "POST="])
        if not opts:
            doc = """
This is a sql blind injection script for ctf
////////////////////////////////////////////////////////
use help:
[*] -u <url>
[*] -h/--help   [helps]
[*] -b [chose blind type]
[*] --GET [use GET request]
[*] --POST="<post data>" [use POST request  attention! you must add double quote in here]

选择盲注方式
    [+] 基于时间盲注 输入 -b 1
    [+] 基于报错盲注 输入 -b 2
    [+] 普通特征盲注 输入 -b 3
    
///////////////////////////////////////////////////////
            """
            print(doc)

    except getopt.GetoptError:
        print('sqlblind.py -u <url> --GET[--POST]')
        sys.exit(2)

    for arg, opt in opts:
        if arg == '-u':
            url = opt


        if arg == '-b':
            base = opt


        if arg == '--GET':
            b = base
            a = blind.Blind(url, b)
            a.start()
        if arg == '--POST':

            datas = opt
            b = blind.BlindPost(url, datas, base)
            b.start()

        if arg == '-h' or arg == '--help' or opts == []:
            print("输入格式 如 python sqlblind.py -u http://xxxx.com -b <base> --GET ")


if __name__ == '__main__':
    print("*******注意 请在参数后不要加 但引号 或 双引号")
    print("********注意 post 参数两边必须加上双引号")
    main()
