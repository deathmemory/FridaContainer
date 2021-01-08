/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: jnimgr.js
 * @time: 2020/6/18 5:14 PM
 * @desc:
 */
import {FCCommon} from "../FCCommon"
import {DMLog} from "../dmlog";
import {MethodData} from "./jni/method_data";
// @ts-ignore
import JNI_ENV_METHODS from "./jni/jni_env.json";
// struct JNINativeInterface :
// https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
const jni_struct_array = [
    "reserved0",
    "reserved1",
    "reserved2",
    "reserved3",
    "GetVersion",
    "DefineClass",
    "FindClass",
    "FromReflectedMethod",
    "FromReflectedField",
    "ToReflectedMethod",
    "GetSuperclass",
    "IsAssignableFrom",
    "ToReflectedField",
    "Throw",
    "ThrowNew",
    "ExceptionOccurred",
    "ExceptionDescribe",
    "ExceptionClear",
    "FatalError",
    "PushLocalFrame",
    "PopLocalFrame",
    "NewGlobalRef",
    "DeleteGlobalRef",
    "DeleteLocalRef",
    "IsSameObject",
    "NewLocalRef",
    "EnsureLocalCapacity",
    "AllocObject",
    "NewObject",
    "NewObjectV",
    "NewObjectA",
    "GetObjectClass",
    "IsInstanceOf",
    "GetMethodID",
    "CallObjectMethod",
    "CallObjectMethodV",
    "CallObjectMethodA",
    "CallBooleanMethod",
    "CallBooleanMethodV",
    "CallBooleanMethodA",
    "CallByteMethod",
    "CallByteMethodV",
    "CallByteMethodA",
    "CallCharMethod",
    "CallCharMethodV",
    "CallCharMethodA",
    "CallShortMethod",
    "CallShortMethodV",
    "CallShortMethodA",
    "CallIntMethod",
    "CallIntMethodV",
    "CallIntMethodA",
    "CallLongMethod",
    "CallLongMethodV",
    "CallLongMethodA",
    "CallFloatMethod",
    "CallFloatMethodV",
    "CallFloatMethodA",
    "CallDoubleMethod",
    "CallDoubleMethodV",
    "CallDoubleMethodA",
    "CallVoidMethod",
    "CallVoidMethodV",
    "CallVoidMethodA",
    "CallNonvirtualObjectMethod",
    "CallNonvirtualObjectMethodV",
    "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod",
    "CallNonvirtualBooleanMethodV",
    "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod",
    "CallNonvirtualByteMethodV",
    "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod",
    "CallNonvirtualCharMethodV",
    "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod",
    "CallNonvirtualShortMethodV",
    "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod",
    "CallNonvirtualIntMethodV",
    "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod",
    "CallNonvirtualLongMethodV",
    "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod",
    "CallNonvirtualFloatMethodV",
    "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod",
    "CallNonvirtualDoubleMethodV",
    "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod",
    "CallNonvirtualVoidMethodV",
    "CallNonvirtualVoidMethodA",
    "GetFieldID",
    "GetObjectField",
    "GetBooleanField",
    "GetByteField",
    "GetCharField",
    "GetShortField",
    "GetIntField",
    "GetLongField",
    "GetFloatField",
    "GetDoubleField",
    "SetObjectField",
    "SetBooleanField",
    "SetByteField",
    "SetCharField",
    "SetShortField",
    "SetIntField",
    "SetLongField",
    "SetFloatField",
    "SetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethod",
    "CallStaticObjectMethodV",
    "CallStaticObjectMethodA",
    "CallStaticBooleanMethod",
    "CallStaticBooleanMethodV",
    "CallStaticBooleanMethodA",
    "CallStaticByteMethod",
    "CallStaticByteMethodV",
    "CallStaticByteMethodA",
    "CallStaticCharMethod",
    "CallStaticCharMethodV",
    "CallStaticCharMethodA",
    "CallStaticShortMethod",
    "CallStaticShortMethodV",
    "CallStaticShortMethodA",
    "CallStaticIntMethod",
    "CallStaticIntMethodV",
    "CallStaticIntMethodA",
    "CallStaticLongMethod",
    "CallStaticLongMethodV",
    "CallStaticLongMethodA",
    "CallStaticFloatMethod",
    "CallStaticFloatMethodV",
    "CallStaticFloatMethodA",
    "CallStaticDoubleMethod",
    "CallStaticDoubleMethodV",
    "CallStaticDoubleMethodA",
    "CallStaticVoidMethod",
    "CallStaticVoidMethodV",
    "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField",
    "GetStaticBooleanField",
    "GetStaticByteField",
    "GetStaticCharField",
    "GetStaticShortField",
    "GetStaticIntField",
    "GetStaticLongField",
    "GetStaticFloatField",
    "GetStaticDoubleField",
    "SetStaticObjectField",
    "SetStaticBooleanField",
    "SetStaticByteField",
    "SetStaticCharField",
    "SetStaticShortField",
    "SetStaticIntField",
    "SetStaticLongField",
    "SetStaticFloatField",
    "SetStaticDoubleField",
    "NewString",
    "GetStringLength",
    "GetStringChars",
    "ReleaseStringChars",
    "NewStringUTF",
    "GetStringUTFLength",
    "GetStringUTFChars",
    "ReleaseStringUTFChars",
    "GetArrayLength",
    "NewObjectArray",
    "GetObjectArrayElement",
    "SetObjectArrayElement",
    "NewBooleanArray",
    "NewByteArray",
    "NewCharArray",
    "NewShortArray",
    "NewIntArray",
    "NewLongArray",
    "NewFloatArray",
    "NewDoubleArray",
    "GetBooleanArrayElements",
    "GetByteArrayElements",
    "GetCharArrayElements",
    "GetShortArrayElements",
    "GetIntArrayElements",
    "GetLongArrayElements",
    "GetFloatArrayElements",
    "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements",
    "ReleaseByteArrayElements",
    "ReleaseCharArrayElements",
    "ReleaseShortArrayElements",
    "ReleaseIntArrayElements",
    "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements",
    "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion",
    "GetByteArrayRegion",
    "GetCharArrayRegion",
    "GetShortArrayRegion",
    "GetIntArrayRegion",
    "GetLongArrayRegion",
    "GetFloatArrayRegion",
    "GetDoubleArrayRegion",
    "SetBooleanArrayRegion",
    "SetByteArrayRegion",
    "SetCharArrayRegion",
    "SetShortArrayRegion",
    "SetIntArrayRegion",
    "SetLongArrayRegion",
    "SetFloatArrayRegion",
    "SetDoubleArrayRegion",
    "RegisterNatives",
    "UnregisterNatives",
    "MonitorEnter",
    "MonitorExit",
    "GetJavaVM",
    "GetStringRegion",
    "GetStringUTFRegion",
    "GetPrimitiveArrayCritical",
    "ReleasePrimitiveArrayCritical",
    "GetStringCritical",
    "ReleaseStringCritical",
    "NewWeakGlobalRef",
    "DeleteWeakGlobalRef",
    "ExceptionCheck",
    "NewDirectByteBuffer",
    "GetDirectBufferAddress",
    "GetDirectBufferCapacity",
    "GetObjectRefType"
];

export namespace Jni {

    /* Calculate the given funcName address from the JNIEnv pointer */
    export function getJNIFunctionAdress(jnienv_addr: NativePointer, func_name: string) {
        var offset = jni_struct_array.indexOf(func_name) * Process.pointerSize;
        return jnienv_addr.add(offset).readPointer();
    }

    export function getJNIAddr(name: string) {
        var env = Java.vm.getEnv();
        var env_ptr = env.handle.readPointer();
        const addr = Jni.getJNIFunctionAdress(env_ptr, name);
        // DMLog.d('Jni.getJNIAddr', 'addr: ' + addr);
        return addr;
    }

    export function hookJNI(name: string, callbacksOrProbe: InvocationListenerCallbacks | InstructionProbeCallback,
                   data?: NativePointerValue) {
        const addr = Jni.getJNIAddr(name);
        return Interceptor.attach(addr, callbacksOrProbe);
    }

    /**
     * 分离仓库地址：https://github.com/deathmemory/fridaRegstNtv
     */
    export function hook_registNatives() {
        const tag = 'fridaRegstNtv';
        Jni.hookJNI("RegisterNatives", {
            onEnter: function (args) {
                var env = Java.vm.getEnv();
                var p_size = Process.pointerSize;
                var methods = args[2];
                var methodcount = args[3].toInt32();
                // 获取类名
                var name = env.getClassName(args[1]);
                DMLog.i(tag, "==== class: " + name + " ====");
                DMLog.i(tag, "==== methods: " + methods + " nMethods: " + methodcount + " ====");
                /** 根据函数结构原型遍历动态注册信息
                 typedef struct {
                    const char* name;
                    const char* signature;
                    void* fnPtr;
                 } JNINativeMethod;
                 jint RegisterNatives(JNIEnv* env, jclass clazz, const JNINativeMethod* methods, jint nMethods)
                 */
                for (var i = 0; i < methodcount; i++) {
                    var idx = i * p_size * 3;
                    var fnPtr = methods.add(idx + p_size * 2).readPointer();
                    const module = Process.getModuleByAddress(fnPtr);
                    if (module) {
                        const modulename = module.name;
                        const modulebase = module.base;
                        var logstr = "name: " + methods.add(idx).readPointer().readCString()
                            + ", signature: " + methods.add(idx + p_size).readPointer().readCString()
                            + ", fnPtr: " + fnPtr
                            + ", modulename: " + modulename + " -> base: " + modulebase;
                        if (null != modulebase) {
                            logstr += ", offset: " + fnPtr.sub(modulebase);
                        }
                        DMLog.i(tag, logstr);
                    }
                    else {
                        DMLog.e(tag, 'module is null');
                    }
                }
            }
        });
    }

    /**
     * trace 所有 Jni 方法
     * 可以配合 `python/android/traceLogCleaner.py` 脚本，格式化输出日志
     */
    export function traceAllJNISimply() {
        // 遍历 Hook Jni 函数
        jni_struct_array.forEach(function (func_name, idx) {
            if (!func_name.includes("reserved")) {
                Jni.hookJNI(func_name, {
                    onEnter(args) {
                        // 触发时将信息保存到对象中
                        let md = new MethodData(this.context, func_name, JNI_ENV_METHODS[idx], args);
                        this.md = md;
                    },
                    onLeave(retval) {
                        // 退出时将返回值追加到对象中
                        this.md.setRetval(retval);
                        // 发送日志
                        send(JSON.stringify({tid: this.threadId, status: "jnitrace", data: this.md}));
                    }
                });
            }
        })
    }
}