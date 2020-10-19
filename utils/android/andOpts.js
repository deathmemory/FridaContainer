"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
///<reference path="unpack/fridaUnpack.js"/>
const dmlog_1 = require("../dmlog");
/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
const fridaUnpack = require('./unpack/fridaUnpack');
const jni = require('./jni_struct');
class AndOpts {
    static showStacks() {
        Java.perform(function () {
            dmlog_1.DMLog.d('showStacks', Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())); // 打印堆栈
        });
    }
    static hook_uri(bShowStacks) {
        // android.net.Uri
        const Uri = Java.use('android.net.Uri');
        Uri.parse.implementation = function (str) {
            dmlog_1.DMLog.i('hook_uri', 'str: ' + str);
            if (bShowStacks) {
                AndOpts.showStacks();
            }
            return this.parse(str);
        };
    }
    static hook_url(bShowStacks) {
        // java.net.URL;
        const URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url) {
            dmlog_1.DMLog.i('hook_url', 'url: ' + url);
            if (bShowStacks) {
                AndOpts.showStacks();
            }
            return this.$init(url);
        };
    }
    static hook_JSONObject_getString(pKey) {
        const JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getString.implementation = function (key) {
            if (key == pKey) {
                dmlog_1.DMLog.i('hook_JSONObject_getString', 'found key: ' + key);
                AndOpts.showStacks();
            }
            return this.getString(key);
        };
    }
    static hook_fastJson(pKey) {
        // coord: (106734,0,22) | addr: Lcom/alibaba/fastjson/JSONObject; | loc: ?
        const fastJson = Java.use('com/alibaba/fastjson/JSONObject');
        fastJson.getString.implementation = function (key) {
            if (key == pKey) {
                dmlog_1.DMLog.i('hook_fastJson getString', 'found key: ' + key);
                AndOpts.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONArray.implementation = function (key) {
            if (key == pKey) {
                dmlog_1.DMLog.i('hook_fastJson getJSONArray', 'found key: ' + key);
                AndOpts.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getJSONObject.implementation = function (key) {
            if (key == pKey) {
                dmlog_1.DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                AndOpts.showStacks();
            }
            return this.getString(key);
        };
        fastJson.getInteger.implementation = function (key) {
            if (key == pKey) {
                dmlog_1.DMLog.i('hook_fastJson getJSONObject', 'found key: ' + key);
                AndOpts.showStacks();
            }
            return this.getString(key);
        };
    }
    static hook_Map(pKey, accurately) {
        const Map = Java.use('java.util.Map');
        Map.put.implementation = function (key, val) {
            var bRes = false;
            if (accurately) {
                bRes = (key + "") == (pKey);
            }
            else {
                bRes = (key + "").indexOf(pKey) > -1;
            }
            if (bRes) {
                dmlog_1.DMLog.i('map', 'key: ' + key);
                dmlog_1.DMLog.i('map', 'val: ' + val);
                AndOpts.showStacks();
            }
            this.put(key, val);
        };
        const LinkedHashMap = Java.use('java.util.LinkedHashMap');
        LinkedHashMap.put.implementation = function (key1, val) {
            var bRes = false;
            if (accurately) {
                bRes = (key1 + "") == (pKey);
            }
            else {
                bRes = (key1 + "").indexOf(pKey) > -1;
            }
            if (null != key1 && bRes) {
                dmlog_1.DMLog.i('LinkedHashMap', 'key: ' + key1);
                dmlog_1.DMLog.i('LinkedHashMap', 'val: ' + val);
                AndOpts.showStacks();
            }
            return this.put(key1, val);
        };
    }
    static hook_log() {
        const Log = Java.use('android.util.Log');
        Log.d.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log d', 'tag: ' + tag + ', content: ' + content);
        };
        Log.v.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log v', 'tag: ' + tag + ', content: ' + content);
        };
        Log.i.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log i', 'tag: ' + tag + ', content: ' + content);
        };
        Log.w.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log w', 'tag: ' + tag + ', content: ' + content);
        };
        Log.e.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log e', 'tag: ' + tag + ', content: ' + content);
        };
        Log.wtf.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag, content) {
            dmlog_1.DMLog.i('Log wtf', 'tag: ' + tag + ', content: ' + content);
        };
    }
    static dump_dex_common() {
        fridaUnpack.dump_dex_common();
    }
    static traceLoadlibrary() {
        const dlopen_ptr = Module.findExportByName(null, 'dlopen');
        if (null != dlopen_ptr) {
            dmlog_1.DMLog.i('traceLoadlibrary', 'dlopen_ptr: ' + dlopen_ptr);
            Interceptor.attach(dlopen_ptr, {
                onEnter: function (args) {
                    dmlog_1.DMLog.i('traceLoadlibrary', 'loadlibrary: ' + args[0].readCString());
                }
            });
        }
        else {
            dmlog_1.DMLog.e('traceLoadlibrary', 'dlopen_ptr is null');
        }
    }
    static showModules() {
        const modules = Process.enumerateModules();
        modules.forEach(function (value, index, array) {
            dmlog_1.DMLog.i('showModules', JSON.stringify(value));
        });
    }
    static traceFopen() {
        const open_ptr = Module.findExportByName(null, 'fopen');
        if (null != open_ptr) {
            dmlog_1.DMLog.i('traceFopen', 'fopen_ptr: ' + open_ptr);
            Interceptor.attach(open_ptr, {
                onEnter: function (args) {
                    dmlog_1.DMLog.i('traceFopen', 'file_path: ' + args[0].readCString());
                }
            });
        }
        else {
            dmlog_1.DMLog.e('traceFopen', 'fopen_ptr is null');
        }
    }
    /**
     * 写内存
     * @param {NativePointer} addr
     * @param {string} str
     */
    static writeMemory(addr, str) {
        Memory.protect(addr, str.length, 'rwx');
        addr.writeAnsiString(str);
    }
    /**
     * 将 js object 转换成 Java String
     * @param res
     * @returns {any}
     */
    static newString(res) {
        const String = Java.use('java.lang.String');
        return String.$new(res);
    }
}
exports.AndOpts = AndOpts;
