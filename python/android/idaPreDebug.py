# coding=utf-8
import os
import time

'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: pass.py
@time: 2020/11/9 7:43 下午
@desc: 启动 app 挂起， 附加 IDA 后按回车键继续运行
'''

# 穿越
packagename = "com.autonavi.cprotectortest"
launcherAct = "com.autonavi.cprotectortest.MainActivity"


def getPidByLine(line):
    retarray = line.split(" ")
    for cell in retarray:
        if cell.isdigit():
            return cell
    return None


def killLastProc():
    os.system("adb shell am force-stop " + packagename)
    retval = os.popen("adb shell ps | grep " + packagename)
    line = retval.readline()
    pid = getPidByLine(line)
    if pid is not None:
        os.system("adb shell su -c kill -9 " + pid)
    print("kill last proc")


def main():
    killLastProc()

    lauchFull = packagename + "/" + launcherAct
    os.system("adb shell am start -D -n " + lauchFull)
    time.sleep(1)
    retval = os.popen("adb shell ps | grep " + packagename)
    line = retval.readline()
    print("ps line:\n" + line)
    pid = getPidByLine(line)
    print("pid: " + pid)
    adbforward = "adb forward tcp:7788 jdwp:" + pid
    os.system(adbforward)
    print(adbforward)
    raw_input("wait for ida attach ...\nif ida has been attached press [Enter] key")
    jdbconnect = "jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=7788"
    os.system(jdbconnect)
    print(jdbconnect)


if __name__ == '__main__':
    main()
