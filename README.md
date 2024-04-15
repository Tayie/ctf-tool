# sql blind tool

a sql-blind tool for ctf

python version:  python3 (>=3.6)



use help:

- you can choose the two request method to use this script : POST & GET 
- for ctf  you can use the default payload or change it by yourself.
- the details you can open it in terminal by use command `python sqlblind.py -h /--help`

- welcome the more ctfer help me improve this script.

- Attention this script only can be used in mysql

中文：

这是一个Python脚本，用于执行SQL盲注攻击。

- 该脚本支持两种请求方法：POST和GET
- 对于CTF竞赛，你可以使用默认的Payload，或者根据需要自行修改。
- 要查看更多细节，你可以在终端中运行以下命令：`python sqlblind.py -h` 或 `python sqlblind.py --help`。
- 欢迎更多的ctfer来帮助我改善这个脚本
- 本脚本只适用mysql及相关系列



### Update log

#### 20240414：更新2.0版本 基于时间 布尔 报错的三种盲注(post & get)

- 部分模块存在未经测试的bug 等待完善 几天爆肝到1000行 肝不动了
- 希望大家多提建议改善
