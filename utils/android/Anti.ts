/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import {FCAnd} from "../FCAnd";
import {DMLog} from "../dmlog";
import {FCCommon} from "../FCCommon";

const anti_InMemoryDexClassLoader = require("./anti/AntiDexLoader");
const sslPinningPass = require("./repinning");

export class Anti {

    static tag = 'Anti';

    static anti_InMemoryDexClassLoader(callbackfunc: any) {
        anti_InMemoryDexClassLoader(callbackfunc);
    }

    static anti_debug() {
        this.anti_fgets();
        this.anti_exit();
        this.anti_fork();
        this.anti_kill();
        this.anti_ptrace();
    }

    static anti_exit() {
        const exit_ptr = Module.findExportByName(null, 'exit');
        if (null == exit_ptr) {
            return;
        }
        Interceptor.replace(exit_ptr, new NativeCallback(function (code) {
            if (null == this) {
                return 0;
            }
            var lr = FCCommon.getLR(this.context);
            DMLog.i('exit debug', 'entry, lr: ' + lr);
            return 0;
        }, 'int', ['int', 'int']));
    }

    static anti_kill() {
        const kill_ptr = Module.findExportByName(null, 'kill');
        if (null == kill_ptr) {
            return;
        }
        Interceptor.replace(kill_ptr, new NativeCallback(function (ptid, code) {
            if (null == this) {
                return 0;
            }
            var lr = FCCommon.getLR(this.context);
            DMLog.i('kill debug', 'entry, lr: ' + lr);
            return 0;
        }, 'int', ['int', 'int']));
    }

    /**
     * @state_name: cat /proc/xxx/stat ==> ...(<state_name>) S...
     *
     * anti fgets function include : status->TracerPid, State->(tracing stop)
     * ptrace_stop, (package) t, SigBlk
     */
    static anti_fgets() {
        const fgetsPtr = Module.findExportByName(null, 'fgets');
        DMLog.i(Anti.tag, 'anti_fgets: ' + fgetsPtr);
        if (null == fgetsPtr) {
            return;
        }
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
            if (null == this) {
                return 0;
            }
            const lr = FCCommon.getLR(this.context);
            var bufstr = (buffer as NativePointer).readCString();
            var buf_str;

            if (null != bufstr) {
                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    // dmLogout("tracerpid replaced: " + Memory.readUtf8String(buffer));
                    DMLog.i('anti_fgets', "TracePid_res:" + buffer.readCString() + ' lr: ' + lr);
                }
                //State:	S (sleeping)
                if(bufstr.indexOf("State:\tt (tracing stop)") > -1){
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    DMLog.i('anti_fgets', "State_res:" + buffer.readCString());
                }

                if(bufstr.indexOf("ptrace_stop") > -1){
                    buffer.writeUtf8String("sys_epoll_wait");
                    DMLog.i('anti_fgets', "wchan_res:" + buffer.readCString());
                }

                var state_name = "";
                //(sankuai.meituan) t
                if (null != state_name) {
                    var name_t = state_name + ") t";
                    var name_s = state_name + ") S";
                    if(bufstr.indexOf(name_t) > -1){
                        buf_str = bufstr;
                        buffer.writeUtf8String(buf_str.replace(name_t, name_s));
                        DMLog.i('anti_fgets', "stat_res:" + buffer.readCString());
                    }
                }

                // SigBlk
                if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001000');
                    DMLog.i('anti_fgets', "SigBlk_res:" + buffer.readCString());
                }
            }

            var retval = fgets(buffer, size, fp);
            return retval;
        }, 'pointer', ['pointer', 'int', 'pointer']));
    }

    static anti_ptrace() {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (null != ptrace) {
            ptrace = ptrace.or(1);
            DMLog.i('anti_ptrace', "ptrace addr: " + ptrace);
            // Interceptor.attach(ptrace, {
            //     onEnter: function (args) {
            //         DMLog.i('anti_ptrace', 'entry');
            //     }
            // });
            Interceptor.replace(ptrace.or(1), new NativeCallback(function (p1:any, p2: any, p3: any, p4: any) {
                DMLog.i('anti_ptrace', 'entry');
                return 1;
            },'long', ['int', "int", 'pointer', 'pointer']));
        }
    }

    /**
     * 适用于每日优鲜的反调试
     */
    static anti_fork() {
        var fork_addr = Module.findExportByName(null, "fork");
        DMLog.i('anti_ptrace', "fork_addr : " + fork_addr);
        if (null != fork_addr) {
            // Interceptor.attach(fork_addr, {
            //     onEnter: function (args) {
            //         DMLog.i('fork_addr', 'entry');
            //     }
            // });
            Interceptor.replace(fork_addr, new NativeCallback(function () {
                DMLog.i('fork_addr', 'entry');
                return -1;
            },'int', []));
        }
    }

    static anti_sslPinning(cerPath: string) {
        sslPinningPass.ssl_pinning_pass(cerPath);
    }
}
