import {DMLog} from "../dmlog";

/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: anti.js
 * @time: 2021/12/30 4:37 下午
 * @desc:
 */

export namespace AntiIOS {
    export function anti_ptrace() {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (null != ptrace) {
            DMLog.i('anti_ptrace', "ptrace addr: " + ptrace);
            Interceptor.replace(ptrace, new NativeCallback(function (p1: any, p2: any, p3: any, p4: any) {
                DMLog.i('anti_ptrace', 'entry');
                return 1;
            }, 'long', ['int', "int", 'pointer', 'pointer']));
        }
    }
}