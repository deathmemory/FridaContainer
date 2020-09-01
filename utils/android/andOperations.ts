///<reference path="unpack/fridaUnpack.js"/>
import {DMLog} from "../dmlog";
import {FaceBook} from "../../agent/fb/fb";
const fridaUnpack = require('./unpack/fridaUnpack');
import getModuleByAddress = Process.getModuleByAddress;
// const jni = require('./utils/jni_struct');
const jni = require('../jni_struct');

export class AndOperations {
    static showStacks() {
        Java.perform(function () {
            DMLog.d('showStacks', Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));  // 打印堆栈
        });
    }

    static hook_uri(bShowStacks: boolean) {
        // android.net.Uri
        const Uri = Java.use('android.net.Uri');
        Uri.parse.implementation = function (str: string) {
            DMLog.i(FaceBook.TAG + ' uri', 'str: ' + str);
            if (bShowStacks) {
                AndOperations.showStacks();
            }
            return this.parse(str);
        }
    }

    static hook_url(bShowStacks: boolean) {
        // java.net.URL;
        const URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url: string) {
            DMLog.i(FaceBook.TAG + ' hook_url', 'url: ' + url);
            if (bShowStacks) {
                AndOperations.showStacks();
            }
            return this.$init(url);
        }
    }

    static hook_JSONObject_getString(pKey: string) {
        const JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getString.implementation = function (key: string) {
            if(key == pKey) {
                DMLog.i('hook_JSONObject_getString', 'found key: ' + key);
                AndOperations.showStacks();
            }
            return this.getString(key);
        }
    }

    static hook_fastJson(pKey: string) {
        // coord: (106734,0,22) | addr: Lcom/alibaba/fastjson/JSONObject; | loc: ?
        const fastJson = Java.use('com/alibaba/fastjson/JSONObject');
        fastJson.getString.implementation = function (key: string) {
            if(key == pKey) {
                DMLog.i('hook_fastJson getString', 'found key: ' + key);
                AndOperations.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONArray.implementation = function (key: string) {
            if(key == pKey) {
                DMLog.i('hook_fastJson getJSONArray', 'found key: ' + key);
                AndOperations.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONObject.implementation = function (key: string) {
            if(key == pKey) {
                DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                AndOperations.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getInteger.implementation = function (key: string) {
            if(key == pKey) {
                DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                AndOperations.showStacks();
            }
            return this.getString(key);
        };
    }

    static hook_Map(pKey: string, accurately: boolean) {
        const Map = Java.use('java.util.Map');
        Map.put.implementation = function (key: string, val: string) {
            var bRes = false;
            if (accurately) {
                bRes = (key+"") == (pKey);
            }
            else {
                bRes = (key+"").indexOf(pKey) > -1;
            }
            if (bRes) {
                DMLog.i('map', 'key: ' + key);
                DMLog.i('map', 'val: ' + val);
                AndOperations.showStacks();
            }
            this.put(key, val);
        };

        const LinkedHashMap = Java.use('java.util.LinkedHashMap');
        LinkedHashMap.put.implementation = function (key1: any, val: any) {
            var bRes = false;
            if (accurately) {
                bRes = (key1+"") == (pKey);
            }
            else {
                bRes = (key1+"").indexOf(pKey) > -1;
            }
            if (null != key1 && bRes) {
                DMLog.i('LinkedHashMap', 'key: ' + key1);
                DMLog.i('LinkedHashMap', 'val: ' + val);
                AndOperations.showStacks();
            }
            return this.put(key1, val);
        };
    }

    static hook_log() {
        const Log = Java.use('android.util.Log');
        Log.d.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log d', 'tag: ' + tag + ', content: ' + content);
        };
        Log.v.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log v', 'tag: ' + tag + ', content: ' + content);
        };
        Log.i.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log i', 'tag: ' + tag + ', content: ' + content);
        };
        Log.w.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log w', 'tag: ' + tag + ', content: ' + content);
        };
        Log.e.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log e', 'tag: ' + tag + ', content: ' + content);
        };
        Log.wtf.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log wtf', 'tag: ' + tag + ', content: ' + content);
        };
    }

    static getLR(context: CpuContext) {
        if (Process.arch == 'arm') {
            return (context as ArmCpuContext).lr;
        }
        else if (Process.arch == 'arm64') {
            return (context as Arm64CpuContext).lr;
        }
        return ptr(0);
    }

    static getModuleByAddr(addr: NativePointer) {
        var result = 'null';
        Process.enumerateModules().forEach(function (module: Module) {
            if(module.base <= addr && addr <= (module.base.add(module.size))) {
                result = JSON.stringify(module);
                return false; // 跳出循环
            }
        });
        return result;
    }

    /**
     * 打印指定层数的 sp，并指向 so (如果有）
     * @param {CpuContext} context
     * @param {number} number
     */
    static getStacksModInfo(context: CpuContext, number: number) {
        var sp: NativePointer;
        if (Process.arch == 'arm') {
            sp = (context as ArmCpuContext).sp;
        }
        else if (Process.arch == 'arm64') {
            sp = (context as Arm64CpuContext).sp;
        }
        else {
            return;
        }

        for (var i = 0; i < number; i++) {
            var curSp = sp.add(Process.pointerSize * i);
            DMLog.i('And getStacksModInfo', 'curSp: ' + curSp + ', val: ' + curSp.readPointer()
                + ', module: ' + AndOperations.getModuleByAddr(curSp.readPointer()));
        }
    }

    static unpack_common() {
        fridaUnpack.unpack_common();
    }

    static traceLoadlibrary() {
        const dlopen_ptr = Module.findExportByName(null, 'dlopen');
        if (null != dlopen_ptr) {
            DMLog.i('traceLoadlibrary', 'dlopen_ptr: ' + dlopen_ptr);
            Interceptor.attach(dlopen_ptr, {
                onEnter: function (args) {
                    DMLog.i('traceLoadlibrary', 'loadlibrary: ' + args[0].readCString());
                }
            });
        }
        else {
            DMLog.e('traceLoadlibrary', 'dlopen_ptr is null');
        }
    }

    static showModules() {
        const modules = Process.enumerateModules();
        modules.forEach(function (value, index, array) {
            DMLog.i('showModules', JSON.stringify(value));
        })
    }

    static traceFopen() {
        const open_ptr = Module.findExportByName(null, 'fopen');
        if (null != open_ptr) {
            DMLog.i('traceFopen', 'fopen_ptr: ' + open_ptr);
            Interceptor.attach(open_ptr, {
                onEnter: function (args) {
                    DMLog.i('traceFopen', 'file_path: ' + args[0].readCString());
                }
            });
        }
        else {
            DMLog.e('traceFopen', 'fopen_ptr is null');
        }
    }

    static writeMemory(addr: NativePointer, str: string) {
        Memory.protect(addr, str.length, 'rwx');
        addr.writeAnsiString(str);

    }

    static newString(res: any) {
        const String = Java.use('java.lang.String');
        return String.$new(res);
    }

    static getJniAddr(jnimethod: string) {
        var env = Java.vm.getEnv();
        var env_ptr = env.handle.readPointer();
        const addr = jni.getJNIFunctionAdress(env_ptr, 'GetStringUTFChars');
        return addr;
    }
}