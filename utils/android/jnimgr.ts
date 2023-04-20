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
    // 定义保存函数名、签名和 jmethodID 的结构体
    type MethodInfo = {
        className: string,
        methodName: string,
        signature: string,
        isStatic: boolean,
    }

    // 保存函数名、签名和 jmethodID 的 Map
    const methodMap = new Map<string, { methodName: string, signature: string, methodId: NativePointer, isStatic: boolean }>();


    var have_record_method_info: Boolean = false;

    export function getJNIFunctionAdress(jnienv_addr: NativePointer, func_name: string) {
        let idx = jni_struct_array.indexOf(func_name);
        if (-1 == idx) {
            DMLog.e('getJNIFunctionAdress', `func name: ${func_name} not found!`);
            return ptr(0);
        }
        var offset = idx * Process.pointerSize;
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
        console.log("Jni.getJNIAddr: " + name + ", addr: " + addr);
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
        jni_struct_array.forEach(traceJNICore);
    }

    export function traceJNI(nameArray: string[]) {
        nameArray.forEach(function (name) {
            let idx = getJNIFunctionIndex(name);
            DMLog.i('traceJNI', 'name: ' + name + 'idx: ' + idx);
            if (-1 != idx) {
                traceJNICore(name, idx);
            }
        });
    }

    export function traceJNICore(func_name: string, idx: number) {
        Jni.record_method_info();
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
    }

    export function getJNIFunctionIndex(funcName: string) {
        return JNI_ENV_METHODS.findIndex(method => method.name === funcName);
    }

    export function record_method_info() {
        if (have_record_method_info == false) {
            // hook GetMethodID 函数
            Jni.hookJNI("GetMethodID", {
                onEnter: function (args) {
                    // const clsObj = Java.cast(args[1], Java.use('java.lang.Class'));
                    this.methodName = args[2].readCString();
                    this.signature = args[3].readCString();
                },
                onLeave: function (retval) {
                    // 保存函数名、签名和 jmethodID 到 Map 中
                    methodMap.set(retval.toString(), {
                        methodName: this.methodName,
                        signature: this.signature,
                        methodId: retval,
                        isStatic: false
                    });
                }
            });

            // hook GetStaticMethodID 函数
            Jni.hookJNI("GetStaticMethodID", {
                onEnter: function (args) {
                    this.methodName = args[2].readCString();
                    this.signature = args[3].readCString();
                },
                onLeave: function (retval) {
                    // 保存函数名、签名和 jmethodID 到 Map 中
                    methodMap.set(retval.toString(), {
                        methodName: this.methodName,
                        signature: this.signature,
                        methodId: retval,
                        isStatic: true
                    });
                }
            });

            have_record_method_info = true;
        }
    }

    // 获取函数名、签名和 jmethodID 的函数
    export function getMethodInfo(methodId: NativePointer) {
        return methodMap.get(methodId.toString());
    }

}