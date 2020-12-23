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
const unpinning = require("./multi_unpinning");

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
     * anti fgets function include :
     * status->TracerPid, SigBlk, S (sleeping)
     * State->(package) S
     * wchan->SyS_epoll_wait
     */
    static anti_fgets() {
        const tag = 'anti_fgets';
        const fgetsPtr = Module.findExportByName(null, 'fgets');
        DMLog.i(Anti.tag, 'fgets addr: ' + fgetsPtr);
        if (null == fgetsPtr) {
            return;
        }
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
            if (null == this) {
                return 0;
            }
            var logTag = null;
            // 进入时先记录现场
            const lr = FCCommon.getLR(this.context);
            // 读取原 buffer
            var retval = fgets(buffer, size, fp);
            var bufstr = (buffer as NativePointer).readCString();

            if (null != bufstr) {
                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    logTag = 'TracerPid';
                }
                //State:	S (sleeping)
                else if (bufstr.indexOf("State:\tt (tracing stop)") > -1) {
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    logTag = 'State';
                }
                // ptrace_stop
                else if (bufstr.indexOf("ptrace_stop") > -1) {
                    buffer.writeUtf8String("sys_epoll_wait");
                    logTag = 'ptrace_stop';
                }

                //(sankuai.meituan) t
                else if (bufstr.indexOf(") t") > -1) {
                    buffer.writeUtf8String(bufstr.replace(") t", ") S"));
                    logTag = 'stat_t';
                }

                // SigBlk
                else if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001204');
                    logTag = 'SigBlk';
                }
                if (logTag) {
                    DMLog.i(tag + " " + logTag, bufstr + " -> " + buffer.readCString() + ' lr: ' + lr
                        + "(" + FCCommon.getModuleByAddr(lr) + ")");
                }
            }
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
            Interceptor.replace(ptrace.or(1), new NativeCallback(function (p1: any, p2: any, p3: any, p4: any) {
                DMLog.i('anti_ptrace', 'entry');
                return 1;
            }, 'long', ['int', "int", 'pointer', 'pointer']));
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
            }, 'int', []));
        }
    }

    static anti_sslLoadCert(cerPath: string) {
        sslPinningPass.ssl_load_cert(cerPath);
    }

    static anti_ssl_unpinning() {
        setTimeout(unpinning.multi_unpinning, 0);
    }
}
