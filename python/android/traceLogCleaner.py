# encoding: utf-8
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: TraceLogCleaner.py
@time: 2020/12/15 7:14 下午
@desc: trace日志清洁工。默认 attach Android 当前打开的应用，接收 trace 内容并按 threadid 分文件记录
        如果检测数据为字符数组，则会尝试转换成 string 到 trystr 字段，也会尝试转换成 hex
        到 tryhex 字段，方便搜索。
        保存结果在脚本同目录下的 tdc_dir 目录中。
'''
import codecs
import json
import os
import shutil
import sys

import frida


class TraceLogCleaner:

    '''
    @bFmt 是否以格式化方式记录日志
    '''
    def __init__(self, bFmt):
        self.saveDir = 'tdc_dir'
        self.bFmt = bFmt
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
        line = line.strip()
        # print ('current line: {}'.format(line))
        jobj = json.loads(line)
        filename = str(jobj['tid'])
        # wash args
        status = jobj['status']
        if status == 'msg':
            result = line
        elif status == 'jnitrace':
            result = line
            if self.bFmt is True:
                fmtstr = self.getJniFormatString(jobj)
                result += '\n' + fmtstr + '\n'
        else:
            if status == 'entry':
                args = list(jobj['args'].values())
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

            result = json.dumps(jobj)
            if self.bFmt is True:
                fmtstr = self.getJavaMethodFormatString(jobj)
                result += '\n' + fmtstr + '\n'

        with open(os.path.join(self.saveDir, filename), 'a+') as f:
            f.write(result)
            f.write('\n')
            f.close()

    def clean(self):
        if os.path.isdir(self.saveDir):
            shutil.rmtree(self.saveDir)

    def washWithSpawn(self, jspath, packagename):
        dev = frida.get_usb_device()
        app_pid = dev.spawn(packagename)
        session = dev.attach(app_pid)
        self._doWash(session, jspath)
        dev.resume(app_pid)

        sys.stdin.read()
        session.detach()

    def _doWash(self, session, jspath):
        with codecs.open(jspath, 'r', 'utf-8') as f:
            jscode = f.read()
            f.close()
            self.mkdirSaveDir()
            script = session.create_script(jscode, runtime="v8")
            # session.enable_jit()
            session.enable_debugger()
            script.on('message', self.onMessage)
            script.load()

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
        try:
            self.washLine(msg['payload'])
        except:
            print('except line: ' + str(msg))

    def getJavaMethodFormatString(self, jobj):
        tryval = jobj['tryval']
        status = jobj['status']
        if status == 'exit':
            try:
                if 'retval' in jobj:
                    tryblock = ''
                    if 'p0' in tryval:
                        tryblock = '\n|(str)== \"{trystr}\"\n|(hex)== {tryhex}'\
                            .format(trystr=tryval['p0']['trystr'], tryhex=tryval['p0']['tryhex'])
                    vals = '|= {retval}{tryblock}'.format(retval=str(jobj['retval']), tryblock=tryblock)
                else:
                    vals = ''
            except:
                print('except exit:', json.dumps(jobj))
        else:
            args = list(jobj['args'].values())
            vals = []
            try:
                for i in range(len(args)):
                    arg = args[i]
                    tryblock = ''
                    if isinstance(arg, list):
                        pkey = 'p%d' % i
                        if pkey in tryval:
                            tryblock = '\n|(str)-- \"{trystr}\"\n|(hex)-- {tryhex}'\
                                .format(trystr=tryval[pkey]['trystr'], tryhex=tryval[pkey]['tryhex'])
                    tmp = '|- {arg}{tryblock}'.format(arg=str(arg), tryblock=tryblock)
                    vals.append(tmp)
            except:
                print('except entry:', json.dumps(jobj))
            vals = '\n'.join(vals)
        fmt = '[+] ({status}) {clsname}\n|-> {methodname}\n{vals}'.format(status=status, clsname=jobj['classname'], methodname=jobj['method'], vals=vals)
        return fmt

    def getJniFormatString(self, jobj):
        try:
            data = jobj['data']
            jnival = data['jnival']
            backtrace = data['backtrace']

            argsfmt = []
            for arg in jnival['args']:
                tmp = '|- {argType}\t\t: {argValue}'.format(argType=arg['argType'].ljust(10, ' '), argValue=arg['argVal'].strip())
                argsfmt.append(tmp)

            backtraceFmt = []
            try:
                for bt in backtrace:
                    tmp = '|-> {address}: ({module_name}:{module_base}) {path}'\
                        .format(address=bt['address'],  module_name=bt['module']['name'], module_base=bt['module']['base'], path=bt['module']['path'])
                    backtraceFmt.append(tmp)
            except:
                pass
            fmt = '[+] {methodname}\n{args}\n|= {retType}\t\t: {retValue}\n|-> BackTrace: \n{backtraceFmt}'\
                .format(methodname=data['methodname'], args='\n'.join(argsfmt),
                        retType=jnival['ret']['retType'].ljust(10, ' '), retValue=jnival['ret']['retVal'].strip(),
                        backtraceFmt='\n'.join(backtraceFmt))
        except:
            print('except:' + json.dumps(jobj))
            return ""
        return fmt



if __name__ == '__main__':
    tdc = TraceLogCleaner(bFmt=True)
    tdc.clean()
    tdc.washOnMessage('../../_fcagent.js')
    # tdc.washWithSpawn('../../_fcagent.js', 'com.baidu.BaiduMap')

    # tdc.washFile(path='tdc_dir/test_31523')

    print ('done !')
