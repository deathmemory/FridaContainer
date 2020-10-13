# encoding: utf-8
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: main.py
@time: 2020/6/8 10:20 AM
@desc:
'''
import codecs
import sys

import frida
import time

def on_message(message, data):
    global _script, url, body
    if message['type'] == 'send':
        try:
            payload = message['payload']
            print(payload)
        except IOError as e:
            print(e)
    else:
        print(message)


def attach(device, packagename):
    session = None
    while session is None:
        print("wait to attach ...")
        try:
            session = device.attach(packagename)
        except frida.ProcessNotFoundError as err:
            print(err)
        time.sleep(1)
    return session


def spawn(device, packagename):
    pid = device.spawn([packagename])
    device.resume(pid)
    session = device.attach(pid)
    return session


def doHook(packagename, scriptfile, bSpawn=False):
    global device, _script
    with codecs.open(scriptfile, "r", "utf-8") as jsfile:
        jscode = jsfile.read()

        if (bSpawn):
            session = spawn(device, packagename)
        else:
            session = attach(device, packagename)

        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()


if __name__ == '__main__':
    # device = frida.get_device_manager()\
    #     .add_remote_device("127.0.0.1:3333")
    device = frida.get_usb_device(1)
    # processes = device.enumerate_processes()

    # doHook("com.sdu.didi.psnger", "frida_didi.js", False)
    # doHook(u'滴滴出行', "OneTravel.js", False);
    # spawn(device, 'com.autonavi.cprotectortest')
    # doHook('com.autonavi.cprotectortest', '_fcagent.js', True)
    # doHook('com.autonavi.minimap', '_fcagent.js', True)
    # doHook('com.ss.android.ugc.aweme', '_fcagent.js', True)
    doHook('com.google.android.apps.maps', '_fcagent.js', True)
    # doHook('com.baidu.BaiduMap', '_fcagent.js', True)

    # script.post({
    #     'type': "input",
    #     'payload': DDUtil.converUrlParams(url) + DDUtil.converBody(body)
    # })

    print("[*] running frida")
    sys.stdin.read()
