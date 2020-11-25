# coding=utf-8
import os
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: pass.py
@time: 2020/11/9 7:43 下午
@desc: 运行 IDA server 脚本
'''

# servername = "dmserv7_64"
servername = "dmserv7"
port = "2333"

def main():
    killserver = "adb shell su -c killall -9 " + servername
    os.system("adb shell su -c killall -9 dmserv7_64")
    os.system("adb shell su -c killall -9 dmserv7")
    print(killserver)
    adbforward = "adb forward tcp:" + port + " tcp:" + port
    os.system(adbforward)
    print(adbforward)
    adbserver = "adb shell su -c /data/local/tmp/" + servername + " -p" + port + " &"
    os.system(adbserver)
    print(adbserver)

if __name__ == '__main__':
    main()
