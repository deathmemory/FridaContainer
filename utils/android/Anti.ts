/**
 * @author: dmemory
 * @contact: 
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import {DMLog} from "../dmlog";
import {FCCommon} from "../FCCommon";
import {FCAnd} from "../FCAnd";


const sslPinningPass = require("./repinning");
const unpinning = require("./multi_unpinning");

export namespace Anti {

    /**
     * 动态加载 dex
     * 在利用 InMemoryDexClassLoader 加载内存 Dex 找不到类的情况下适用。
     * 调用方式：
     * FCAnd.anti.anti_InMemoryDexClassLoader(function(){
     *     const cls = Java.use('find/same/multi/dex/class');
     *     // ...
     * });
     *
     * 实现原理：
     * const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
     InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
     .implementation = function (buff, loader) {
            this.$init(buff, loader);
            var oldcl = Java.classFactory.loader;
            Java.classFactory.loader = this;
            callbackfunc();
            Java.classFactory.loader = oldcl;

            return undefined;
        }
     * @param callbackfunc
     *
     * @deprecated The method should not be used
     */
    export function anti_InMemoryDexClassLoader(callbackfunc: any) {
        throw new Error("deprecated method, should use:  FCAnd.useWithInMemoryDexClassLoader");
    }

    export function anti_1__cxa_throw() {
        const cxa_throw_ptr = Module.findExportByName(null, "__cxa_throw");
        if (null == cxa_throw_ptr) {
            DMLog.e('anti_1__cxa_throw', "_ZSt9__throw_1PKc not found");
            return;
        }
        else {
            DMLog.i('anti_1__cxa_throw', 'addr: ' + cxa_throw_ptr);
        }

        Interceptor.replace(cxa_throw_ptr, new NativeCallback(function () {
            DMLog.i('anti_1__cxa_throw', 'Caught __cxa_throw call (preventing exception)');
            FCAnd.showAllStacks(this.context); // 打印完整堆栈
            // 可选：模拟返回，避免崩溃
            // return ...;
        }, 'void', [])); // 根据实际参数调整类型
    }


    export function anti_debug() {
        anti_fgets();
        anti_exit();
        anti_fork();
        anti_kill();
        anti_ptrace();
        anti_1__cxa_throw();
    }

    export function anti_exit() {
        const exit_ptr = Module.findExportByName(null, '_exit');
        DMLog.i('anti_exit', "exit_ptr : " + exit_ptr);
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

    export function anti_kill() {
        const kill_ptr = Module.findExportByName(null, 'kill');
        DMLog.i('anti_kill', "kill_ptr : " + kill_ptr);

        if (null == kill_ptr) {
            return;
        }
        Interceptor.replace(kill_ptr, new NativeCallback(function (ptid, code) {
            if (null == this) {
                return 0;
            }
            var lr = FCCommon.getLR(this.context);
            DMLog.i('kill debug', 'entry, lr: ' + lr);
            FCAnd.showNativeStacks(this.context);
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
    export function anti_fgets() {
        const tag = 'anti_fgets';
        const fgetsPtr = Module.findExportByName(null, 'fgets');
        DMLog.i(tag, 'fgets addr: ' + fgetsPtr);
        if (null == fgetsPtr) {
            return;
        }
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp): NativePointer {
            var logTag = null;
            // 进入时先记录现场
            const lr = FCCommon.getLR(this.context);
            // 读取原 buffer
            var retval = fgets(buffer, size, fp);
            var bufstr = buffer.readCString();

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

                // frida
                else if (bufstr.indexOf('frida') > -1) {
                    // 直接回写空有可能引起崩溃
                    buffer.writeUtf8String("dmemory");
                    logTag = 'frida';
                }

                if (logTag) {
                    DMLog.i(tag + " " + logTag, bufstr + " -> " + buffer.readCString() + ' lr: ' + lr
                        + "(" + FCCommon.getModuleByAddr(lr) + ")");
                    FCAnd.showNativeStacks(this?.context);
                }
            }
            return retval;
        }, 'pointer', ['pointer', 'int', 'pointer']));
    }

    export function anti_ptrace() {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (null != ptrace) {
            DMLog.i('anti_ptrace', "ptrace addr: " + ptrace);
            // Interceptor.attach(ptrace, {
            //     onEnter: function (args) {
            //         DMLog.i('anti_ptrace', 'entry');
            //     }
            // });
            Interceptor.replace(ptrace, new NativeCallback(function (p1: any, p2: any, p3: any, p4: any) {
                DMLog.i('anti_ptrace', 'entry');
                return 1;
            }, 'long', ['int', "int", 'pointer', 'pointer']));
        }
    }

    /**
     * 适用于每日优鲜的反调试
     */
    export function anti_fork() {
        var fork_addr = Module.findExportByName(null, "fork");
        DMLog.i('anti_fork', "fork_addr : " + fork_addr);
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

    export function anti_sslLoadCert(cerPath: string) {
        sslPinningPass.ssl_load_cert(cerPath);
    }

    export function anti_ssl_unpinning() {
        setTimeout(unpinning.multi_unpinning, 0);
    }

    /**
     * chrome cronet bypass （针对 32 位）
     * 定位：".Android" 字符串，向上引用，查找返回值赋值函数。
     *
     * 搜索特征：
     * 01 06 44 BF 6F F0 CE 00  70 47 81 04 44 BF 6F F0
     * 95 00 70 47 41 01 44 BF  6F F0 D8 00 70 47 41 06
     * 44 BF 6F F0 CD 00 70 47  41 07 44 BF 6F F0 C9 00
     * 70 47 C1 07 1C BF 6F F0  C7 00 70 47 C1 01 44 BF
     */
    export function anti_ssl_cronet_32() {
        var moduleName = "libsscronet.so"; // 模块名
        var searchBytes = '01 06 44 BF 6F F0 CE 00 70 47 81 04 44 BF 6F F0 95 00 70 47 41 01 44 BF 6F F0 D8 00 70 47 41 06 44 BF 6F F0 CD 00 70 47 41 07 44 BF 6F F0 C9 00 70 47 C1 07 1C BF 6F F0 C7 00 70 47 C1 01 44 BF'; // 搜索的特征值

        // 获取模块基址和大小
        var module = Process.getModuleByName(moduleName);
        var baseAddr = module.base;
        var size = module.size;

        // 在模块地址范围内搜索特征值
        var matches = Memory.scan(baseAddr, size, searchBytes, {
            onMatch: function (address, size) {
                DMLog.i("anti_ssl_cronet", "[*] Match found at: " + address);
                // 将地址转换为静态偏移地址
                var offset = address.sub(baseAddr);
                DMLog.i("anti_ssl_cronet", "[+] Static Offset: " + offset);
                Interceptor.attach(address.or(1), {
                    onLeave: function (retval) {
                        retval.replace(ptr(0));
                        DMLog.w('anti_ssl_cronet retval', 'replace value: ' + retval);
                    }
                })
            },
            onComplete: function () {
                DMLog.i("anti_ssl_cronet", "[*] Search completed!");
            }
        });

    }
}
