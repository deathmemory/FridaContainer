/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: jnimgr.js
 * @time: 2020/6/18 5:14 PM
 * @desc:
 */
const DMLog = require("../dmlog");
const jni = require('./jni_struct');

export class Jni {
    static getJNIAddr(name: string) {
        var env = Java.vm.getEnv();
        var env_ptr = env.handle.readPointer();
        const addr = jni.getJNIFunctionAdress(env_ptr, name);
        DMLog.d('Jni.getJNIAddr', 'addr: ' + addr);
        return addr;
    }

    static hookJNI(name: string, callbacksOrProbe: InvocationListenerCallbacks | InstructionProbeCallback,
        data?: NativePointerValue) {
        const addr = Jni.getJNIAddr(name);
        return Interceptor.attach(addr, callbacksOrProbe);
    }
}