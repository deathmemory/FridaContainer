# encoding: utf-8
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: TraceLogCleaner.py
@time: 2020/12/15 7:14 下午
@desc: trace日志清洁工。默认 attach Android 当前打开的应用，接收 trace 内容并按 threadid 分文件记录
        如果检测数据为字符数组，则会尝试转换成 string 到 trystr 字段，也会尝试转换成 hex
        到 tryhex 字段，方便搜索。
'''
import codecs
import json
import os
import shutil
import sys

import frida


class TraceLogCleaner:

    def __init__(self):
        self.saveDir = 'tdc_dir'
        pass

    def washFile(self, path):
        self.mkdirSaveDir()
        with open(path, 'r') as f:
            line = f.readline()
            while (line != ''):
                self.washLine(line)
                line = f.readline()
            f.close()
        pass

    def mkdirSaveDir(self):
        if not os.path.isdir(self.saveDir):
            os.makedirs(self.saveDir)

    def washLine(self, line):
        if line == '':
            return
        # print ('current line: {}'.format(line))
        jobj = json.loads(line)
        filename = str(jobj['tid'])
        # wash args
        status = jobj['status']
        if status == 'entry':
            args = jobj['args']
        else:
            args = []
            if ('retval' in jobj):
                args.append(jobj['retval'])
        if isinstance(args, list):
            tryval = {}
            for i in range(len(args)):
                try:
                    arg = args[i]
                    if isinstance(arg, list):
                        try:
                            trystr = "".join(map(chr, arg))
                        except:
                            trystr = ''
                        try:
                            tryhex = ','.join('{:02x}'.format(x & 0xff) for x in arg)
                        except:
                            tryhex = ''
                        tryval['p{:d}'.format(i)] = {'trystr': trystr, 'tryhex': tryhex}
                except:
                    pass
            jobj['tryval'] = tryval

        with open(os.path.join(self.saveDir, filename), 'a+') as f:
            f.write(json.dumps(jobj))
            f.write('\n')
            f.close()

    def clean(self):
        if os.path.isdir(self.saveDir):
            shutil.rmtree(self.saveDir)

    def washOnMessage(self, jspath):
        with codecs.open(jspath, 'r', 'utf-8') as f:
            jscode = f.read()
            self.mkdirSaveDir()
            dev = frida.get_usb_device()
            app = dev.get_frontmost_application()
            print (app)
            session = dev.attach(app.pid)
            script = session.create_script(jscode, runtime="v8")
            # session.enable_jit()
            session.enable_debugger()
            script.on('message', self.onMessage)
            script.load()
            f.close()
            sys.stdin.read()
            session.detach()
        pass

    def onMessage(self, msg, data):
        self.washLine(msg['payload'])


if __name__ == '__main__':
    tdc = TraceLogCleaner()
    tdc.clean()

    # tdc.washFile(path='/Users/dmemory/Downloads/trace.log')

    tdc.washOnMessage('../../_fcagent.js')
    print ('done !')
