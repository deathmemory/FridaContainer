/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */


const fridaUnpack = require('./android/unpack/fridaUnpack');
import {Anti} from "./android/Anti";
import {Jni} from "./android/jnimgr";
import {FCCommon} from "./FCCommon";
import {DMLog} from "./dmlog";

export namespace FCAnd {
    export const anti = Anti;
    export const jni = Jni;
    export const common = FCCommon;

    export function getStacks() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()) + "";
    }

    export function showStacks() {
        Java.perform(function () {
            DMLog.d('showStacks', getStacks());  // 打印堆栈
        });Process.getCurrentThreadId()
    }

    export function hook_uri(bShowStacks: boolean) {
        // android.net.Uri
        const Uri = Java.use('android.net.Uri');
        Uri.parse.implementation = function (str: string) {
            DMLog.i('hook_uri', 'str: ' + str);
            if (bShowStacks) {
                showStacks();
            }
            return this.parse(str);
        }
    }

    export function hook_url(bShowStacks: boolean) {
        // java.net.URL;
        const URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url: string) {
            DMLog.i('hook_url', 'url: ' + url);
            if (bShowStacks) {
                showStacks();
            }
            return this.$init(url);
        }
    }

    export function hook_JSONObject_getString(pKey: string) {
        const JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getString.implementation = function (key: string) {
            if (key == pKey) {
                DMLog.i('hook_JSONObject_getString', 'found key: ' + key);
                showStacks();
            }
            return this.getString(key);
        }
    }

    export function hook_fastJson(pKey: string) {
        // coord: (106734,0,22) | addr: Lcom/alibaba/fastjson/JSONObject; | loc: ?
        const fastJson = Java.use('com/alibaba/fastjson/JSONObject');
        fastJson.getString.implementation = function (key: string) {
            if (key == pKey) {
                DMLog.i('hook_fastJson getString', 'found key: ' + key);
                showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONArray.implementation = function (key: string) {
            if (key == pKey) {
                DMLog.i('hook_fastJson getJSONArray', 'found key: ' + key);
                showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONObject.implementation = function (key: string) {
            if (key == pKey) {
                DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                showStacks();
            }
            return this.getString(key);
        };
        fastJson.getInteger.implementation = function (key: string) {
            if (key == pKey) {
                DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                showStacks();
            }
            return this.getString(key);
        };
    }

    export function hook_Map(pKey: string, accurately: boolean) {
        const Map = Java.use('java.util.Map');
        Map.put.implementation = function (key: string, val: string) {
            var bRes = false;
            if (accurately) {
                bRes = (key + "") == (pKey);
            }
            else {
                bRes = (key + "").indexOf(pKey) > -1;
            }
            if (bRes) {
                DMLog.i('map', 'key: ' + key);
                DMLog.i('map', 'val: ' + val);
                showStacks();
            }
            this.put(key, val);
        };

        const LinkedHashMap = Java.use('java.util.LinkedHashMap');
        LinkedHashMap.put.implementation = function (key1: any, val: any) {
            var bRes = false;
            if (accurately) {
                bRes = (key1 + "") == (pKey);
            }
            else {
                bRes = (key1 + "").indexOf(pKey) > -1;
            }
            if (null != key1 && bRes) {
                DMLog.i('LinkedHashMap', 'key: ' + key1);
                DMLog.i('LinkedHashMap', 'val: ' + val);
                showStacks();
            }
            return this.put(key1, val);
        };
    }

    export function hook_log() {
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

    export function dump_dex_common() {
        fridaUnpack.dump_dex_common();
    }

    export function traceLoadlibrary() {
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

    export function showModules() {
        const modules = Process.enumerateModules();
        modules.forEach(function (value, index, array) {
            DMLog.i('showModules', JSON.stringify(value));
        })
    }

    export function traceFopen() {
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

    /**
     * 写内存
     * @param {NativePointer} addr
     * @param {string} str
     */
    export function writeMemory(addr: NativePointer, str: string) {
        Memory.protect(addr, str.length, 'rwx');
        addr.writeAnsiString(str);

    }

    /**
     * 将 js object 转换成 Java String
     * @param res
     * @returns {any}
     */
    export function newString(res: any) {
        if (null == res) {
            return null;
        }
        const String = Java.use('java.lang.String');
        return String.$new(res);
    }

    export function getApplicationContext() {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const Context = Java.use('android.content.Context');
        const ctx = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);
        return ctx;
    }

    export function printByteArray(jbytes: any) {
        // return JSON.stringify(jbytes);
        var result = "";
        for (var i = 0; i < jbytes.length; ++i) {
            result += " ";
            result += jbytes[i].toString(16);
        }
        return result;
    }

    /**
     * trace java methods 默认类
     */
    export const tjm_default_cls = [
        // 'E:javax.crypto.Cipher',
        // 'E:javax.crypto.spec.SecretKeySpec',
        // 'E:javax.crypto.spec.IvParameterSpec',
        // 'E:javax.crypto.Mac',
        // 'M:KeyGenerator',
        'M:Base64',
        'M:javax.crypto',
        'M:java.security',
        'E:java.lang.String',
    ];

    /**
     * trace java methods 对 java.lang.String 类中的默认白名单方法名
     */
    export const tjm_default_white_detail: any = {
        /*{ clsname: {white: true/false, methods[a, b, c]} }*/
        'java.lang.String': {white: true, methods: ['toString', 'getBytes']}
    }

    /**
     * 作为 traceJavaMethods 的别称存在
     * @param clazzes
     * @param clsWhitelist
     * @param stackFilter
     */
    export function traceArtMethods(clazzes?: null | string[], clsWhitelist?: null | any, stackFilter?: string) {
        traceJavaMethods(clazzes, clsWhitelist, stackFilter);
    }

    /**
     * java 方法追踪
     * @param clazzes 要追踪类数组 ['M:Base64', 'E:java.lang.String'] ，类前面的 M 代表 match 模糊匹配，E 代表 equal 精确匹配
     * @param clsWhitelist 指定某类方法 Hook 细则，可按白名单或黑名单过滤方法。
     *                  { '类名': {white: true, methods: ['toString', 'getBytes']} }
     * @stackFilter 按匹配字串打印堆栈。如果要匹配 bytes 数组需要十进制无空格字串，例如："104,113,-105"
     */
    export function traceJavaMethods(clazzes?: null | string[], clsWhitelist?: null | any, stackFilter?: string) {
        let dest_cls: string[] = [];
        let dest_white: any = {...tjm_default_white_detail, ...clsWhitelist};
        if (clazzes != null) {
            dest_cls = tjm_default_cls.concat(clazzes);
        }
        else {
            dest_cls = tjm_default_cls;
        }

        traceJavaMethods_custom(dest_cls, dest_white, stackFilter);
    }

    export function traceJavaMethods_custom(clazzes: string[], clsWhitelist?: null | any, stackFilter?: string) {

        function match(destCls: string, curClsName: string) {
            let mode = destCls[0];
            let ex = destCls.substr(2);
            if (mode == 'E') {
                return ex == curClsName;
            }
            else {
                return curClsName.match(ex);
            }
        }

        function sendContent(obj: any) {
            let str = JSON.stringify(obj);
            let stacks = null;
            if (null != stackFilter && str.indexOf(stackFilter) > -1) {
                stacks = getStacks();
                obj['stacks'] = stacks;
                str = JSON.stringify(obj);
            }
            send(str);
        }

        function traceJavaMethodsCore(clsname: string) {
            let cls = Java.use(clsname);
            let methods = cls.class.getDeclaredMethods();
            DMLog.i('traceJavaMethodsCore', 'trace cls: ' + clsname + ', method size: ' + methods.length);
            methods.forEach(function (method: any) {
                let methodName = method.getName();
                DMLog.i('traceJavaMethodsCore.methodname', methodName);
                let detail = null;
                if (null != clsWhitelist) {
                    detail = clsWhitelist[clsname];
                }
                if (null != detail && typeof (detail) == 'object') {
                    if ((detail.methods.indexOf(methodName) > -1) != detail.white) {
                        return true; // next forEach
                    }
                }

                if ('invoke' == methodName || 'getChars' == methodName) {
                    return true;    // 跳过并继续执行下一个 forEach
                }
                let methodOverloads = cls[methodName].overloads;
                if (null != methodOverloads) {
                    methodOverloads.forEach(function (overload: any) {
                        try {
                            overload.implementation = function () {
                                let tid = Process.getCurrentThreadId();
                                let tname = Java.use("java.lang.Thread").currentThread().getName();
                                sendContent({
                                    tid: tid,
                                    status: 'entry',
                                    tname: tname,
                                    classname: clsname,
                                    method: method.toString(),
                                    method_: overload._p[0],
                                    args: arguments
                                });
                                const retval = this[methodName].apply(this, arguments);
                                sendContent({
                                    tid: tid,
                                    status: 'exit',
                                    tname: tname,
                                    classname: clsname,
                                    method: method.toString(),
                                    retval: retval
                                });
                                return retval;
                            }
                        } catch (e) {
                            DMLog.d('overload.implementation exception: ' + overload._p[0], e.toString());
                        }
                    });
                }
            })

            // let consOverloads = cls.$init.overloads;
            // if (null != consOverloads) {
            //     consOverloads.forEach(function (overload: any) {
            //         overload.implementation = function () {
            //             DMLog.i('traceInit_entry',  '================');
            //             let retval = this.$init(arguments);
            //             DMLog.i('traceInit_exit', '-----------------');
            //             return retval;
            //         }
            //     });
            // }
        }

        Java.enumerateLoadedClassesSync().forEach((curClsName, index, array) => {
            clazzes.forEach((destCls) => {
                if (match(destCls, curClsName)) {
                    traceJavaMethodsCore(curClsName);
                    return false; // end forEach
                }
            });
        });
    }
}
