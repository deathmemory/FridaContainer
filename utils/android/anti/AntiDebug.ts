import {DMLog} from "../../dmlog";

export class AntiDebug {

    static tag = 'AntiDebug';

    static anti_debug() {
        const fgets_ptr = Module.findExportByName(null, 'fgets');
        if (null == fgets_ptr) {
            return;
        }
        Interceptor.attach(fgets_ptr, {
            onEnter: function (args) {
                this.buff = args[0];
                this.lr = (this.context as ArmCpuContext).lr;
            },
            onLeave: function (retval) {
                const retstr = this.buff.readCString();
                if (retstr.indexOf('TracerPid:') > -1) {
                    DMLog.i('fgets debug', 'retbuff: ' + retstr + ', lr: ' + this.lr);
                }
            }
        });

        const kill_ptr = Module.findExportByName(null, 'kill');
        if (null == kill_ptr) {
            return;
        }
        Interceptor.replace(kill_ptr, new NativeCallback(function (ptid, code) {
            if (null == this) {
                return 0;
            }
            var lr = (this.context as ArmCpuContext).lr;
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
        DMLog.i(AntiDebug.tag, 'anti_fgets: ' + fgetsPtr);
        if (null == fgetsPtr) {
            return;
        }
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
            var bufstr = (buffer as NativePointer).readCString();
            var buf_str;

            // console.log("hello" );
            if (null != bufstr) {
                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    // dmLogout("tracerpid replaced: " + Memory.readUtf8String(buffer));
                    if (null != this) {
                        console.log("TracePid_res:" + buffer.readCString() + ' lr: ' + (this.context as ArmCpuContext).lr);
                    }
                }
                //State:	S (sleeping)
                if(bufstr.indexOf("State:\tt (tracing stop)") > -1){
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    console.log("State_res:" + buffer.readCString());
                }

                if(bufstr.indexOf("ptrace_stop") > -1){
                    buffer.writeUtf8String("sys_epoll_wait");
                    console.log("wchan_res:" + buffer.readCString());
                }

                var state_name = "";
                //(sankuai.meituan) t
                if (null != state_name) {
                    var name_t = state_name + ") t";
                    var name_s = state_name + ") S";
                    if(bufstr.indexOf(name_t) > -1){
                        buf_str = bufstr;
                        buffer.writeUtf8String(buf_str.replace(name_t, name_s));
                        console.log("stat_res:" + buffer.readCString());
                    }
                }

                // SigBlk
                if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001000');
                    console.log("SigBlk_res:" + buffer.readCString());
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
}