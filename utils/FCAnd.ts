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
    var firstdiscovery = false;

    export function getStacks() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()) + "";
    }

    export function showStacks() {
        Java.perform(function () {
            DMLog.d('showStacks', getStacks());  // 打印堆栈
        });
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
            return 0;
        };
        Log.v.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log v', 'tag: ' + tag + ', content: ' + content);
            return 0;
        };
        Log.i.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log i', 'tag: ' + tag + ', content: ' + content);
            return 0;
        };
        Log.w.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log w', 'tag: ' + tag + ', content: ' + content);
            return 0;
        };
        Log.e.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log e', 'tag: ' + tag + ', content: ' + content);
            return 0;
        };
        Log.wtf.overload('java.lang.String', 'java.lang.String')
            .implementation = function (tag: string, content: string) {
            DMLog.i('Log wtf', 'tag: ' + tag + ', content: ' + content);
            return 0;
        };
    }

    export function dump_dex_common() {
        fridaUnpack.unpack_common();
    }

    /**
     * 以 loadClass 方式 dump dex
     * 调用 FCAnd.dump_dex_loadAllClass() 即可
     * 当程序启动完成后，
     * 调用 rpc.exports.ddc() 即可完成 dump dex
     */
    export function dump_dex_loadAllClass() {
        let tag = 'dd_loadAllClass';
        var dex_maps: Record<string, number> = {};
        var module = Process.findModuleByName("libart.so")!;
        var addr_DefineClass = null;
        var symbols = module.enumerateSymbols();
        for (var index = 0; index < symbols.length; index++) {
            var symbol = symbols[index];
            var symbol_name = symbol.name;
            //这个DefineClass的函数签名是Android9的
            //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
            if (symbol_name.indexOf("ClassLinker") >= 0 &&
                symbol_name.indexOf("DefineClass") >= 0 &&
                symbol_name.indexOf("Thread") >= 0 &&
                symbol_name.indexOf("DexFile") >= 0) {
                DMLog.i(tag, `${symbol_name} : ${symbol.address}`);
                addr_DefineClass = symbol.address;
            }
        }
        DMLog.i(tag, `DefineClass: ${addr_DefineClass}`);
        if (addr_DefineClass) {
            Interceptor.attach(addr_DefineClass, {
                onEnter: function (args) {
                    var dex_file = args[5];
                    //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
                    //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
                    var base = dex_file.add(Process.pointerSize).readPointer();
                    var size = dex_file.add(Process.pointerSize + Process.pointerSize).readUInt();

                    if (dex_maps[String(base)] == undefined) {
                        dex_maps[String(base)] = size;
                        DMLog.i(tag, `hook_dex: ${base}, ${size}`);
                    }
                },
                onLeave: function (retval) {
                }
            });
        }

        function dump_dex() {
            // load_all_class();
            loadAllClass2();
            let tag = 'dump_dex';
            for (var base in dex_maps) {
                var size = dex_maps[base];
                // console.log(base);

                var magic = ptr(base).readCString();
                if (null != magic && magic.indexOf("dex") == 0) {
                    var process_name = FCAnd.getProcessName();
                    DMLog.i(tag, "process_name: " + process_name);
                    if (process_name != "-1") {
                        var dex_path = "/data/data/" + process_name + "/files/" + base + "_" + size.toString(16) + ".dex";
                        DMLog.i(tag, "dex_path: " + dex_path);
                        var fd = new File(dex_path, "wb");
                        if (fd && fd != null) {
                            var dex_buffer = ptr(base).readByteArray(size);
                            if (null != dex_buffer) {
                                fd.write(dex_buffer);
                                fd.flush();
                            }
                            fd.close();
                            DMLog.i(tag, "dump dex success: " + dex_path);
                        }
                    }
                }
            }
        }

        function loadAllClass2() {
            let tag = 'loadAllClass2';
            Java.perform(function () {
                DMLog.i(tag, "---------------Java.enumerateClassLoaders");
                Java.enumerateClassLoadersSync().forEach(function (loader) {
                    try {
                        loadAllClassCore(loader);
                    } catch (e) {
                        DMLog.e(tag, "Java.enumerateClassLoaders error:" + e);
                    }
                });
            });

            function loadAllClassCore(loader: any) {
                let tag = 'loadAllClassCore';
                var clstr = loader.$className.toString();
                DMLog.i(tag, 'classloader: ' + clstr);
                var class_BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
                var pathcl = Java.cast(loader, class_BaseDexClassLoader);
                DMLog.i(tag, ".pathList: " + pathcl.pathList.value);
                var class_DexPathList = Java.use("dalvik.system.DexPathList");
                var dexPathList = Java.cast(pathcl.pathList.value, class_DexPathList);
                DMLog.i(tag, ".dexElements: " + dexPathList.dexElements.value.length);

                var class_DexFile = Java.use("dalvik.system.DexFile");
                var class_DexPathList_Element = Java.use("dalvik.system.DexPathList$Element");
                for (var i = 0; i < dexPathList.dexElements.value.length; i++) {
                    var dexPathList_Element = Java.cast(dexPathList.dexElements.value[i], class_DexPathList_Element);
                    // console.log(".dexFile:", dexPathList_Element.dexFile.value);
                    if (dexPathList_Element.dexFile.value) {
                        //可能为空
                        var dexFile = Java.cast(dexPathList_Element.dexFile.value, class_DexFile);
                        var mcookie = dexFile.mCookie.value;
                        // console.log(".mCookie", dexFile.mCookie.value);
                        if (dexFile.mInternalCookie.value) {
                            // console.log(".mInternalCookie", dexFile.mInternalCookie.value);
                            mcookie = dexFile.mInternalCookie.value;
                        }
                        var classNameArr = dexPathList_Element.dexFile.value.getClassNameList(mcookie);
                        DMLog.i(tag, "DexFile.getClassNameList.length:" + classNameArr.length);
                        DMLog.i(tag, "     |------------Enumerate ClassName Start");
                        for (var i = 0; i < classNameArr.length; i++) {
                            // DMLog.w(tag, "      " + classNameArr[i]);
                            try {
                                loader.loadClass(classNameArr[i]);
                            } catch (e) {
                                DMLog.w(tag, "loadClass warning:" + e);
                            }
                            // if (classNameArr[i].indexOf(TestCalss) > -1) {
                            //     loadClassAndInvoke(cl, classNameArr[i]);
                            // }
                        }
                        DMLog.i(tag, "     |------------Enumerate ClassName End");
                    }
                }

            }
        }

        rpc.exports = {
            ddc() {
                dump_dex();
            }
        }
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

    /**
     * 将 java byte array 打印成 16 进制字符输出
     * @param jbytes
     */
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
     * 打印 java.util.HashMap
     * @param data
     */
    export function printHashMap(data: any) {
        let result = Java.cast(data, Java.use('java.util.HashMap'));
        let keys = result.keySet().toArray(); // 获取键集合并转换为数组
        for (let i = 0; i < keys.length; i++) {
            let key = keys[i];
            let value = result.get(key); // 获取对应的值
            DMLog.i('printHashMap', 'Key: ' + key.toString() + ', Value: ' + value.toString());
        }
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

    /**
     * 去除了默认类，放大了自由度
     * 去除了默认 trace 类的干净方法，需要 trace 任何类，需要自己指定。
     * @param clazzes
     * @param clsWhitelist
     * @param stackFilter
     */
    export function traceJavaMethods_custom(clazzes: string[], clsWhitelist?: null | any, stackFilter?: null | string) {

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
                if (false == firstdiscovery) {
                    obj['firstdiscovery'] = true;
                    firstdiscovery = true;
                }
                str = JSON.stringify(obj);
            }
            send(str);
        }

        function getMethodDescription(clsname: string, overload: any) {
            // @ts-ignore
            let argumentTypes = overload.argumentTypes.map(val => val.className).toString();
            let desc = `${overload.returnType.className} ${clsname}#${overload.methodName}(${argumentTypes})`;
            return desc;
        }

        function traceJavaMethodsCore(clsname: string) {
            const tag = 'traceJavaMethodsCore';
            let detail: { methods: string | any[]; white: boolean; } | null = null;
            if (null != clsWhitelist) {
                detail = clsWhitelist[clsname];
            }
            let cls = Java.use(clsname);
            let methods = cls.class.getDeclaredMethods();
            DMLog.i(tag, 'trace cls: ' + clsname + ', method size: ' + methods.length);
            methods.forEach(function (method: any) {
                let methodName = method.getName();
                // DMLog.i('traceJavaMethodsCore.methodname', methodName);
                if (null != detail && typeof (detail) == 'object') {
                    if ((detail.methods.indexOf(methodName) > -1) != detail.white) {
                        return true; // next forEach
                    }
                }

                if ('invoke' == methodName) {
                    return true;    // 跳过并继续执行下一个 forEach
                }
                let methodOverloads = cls[methodName].overloads;
                if (null != methodOverloads) {
                    methodOverloads.forEach(function (overload: any) {
                        try {
                            let methodDesc = getMethodDescription(clsname, overload);
                            DMLog.i(tag, 'hookmethod: ' + methodDesc);
                            overload.implementation = function () {
                                let tid = Process.getCurrentThreadId();
                                let tname = Java.use("java.lang.Thread").currentThread().getName();
                                sendContent({
                                    tid: tid,
                                    status: 'entry',
                                    tname: tname,
                                    classname: clsname,
                                    method: methodDesc,
                                    args: arguments
                                });

                                let retval = overload.apply(this, arguments);

                                sendContent({
                                    tid: tid,
                                    status: 'exit',
                                    tname: tname,
                                    classname: clsname,
                                    method: methodDesc,
                                    retval: retval
                                });
                                return retval;
                            }
                        }
                        catch (e: any) {
                            DMLog.d(tag, 'overload.implementation exception:\t' + overload.methodName + "\t" + e.toString());
                        }
                    });
                }
            })

            // getConstructors
            let constructors = cls.class.getConstructors();
            if (null != constructors && (null == detail || detail.methods.indexOf('$init') > -1)) {
                try {
                    let methodOverloads = cls['$init'].overloads;
                    methodOverloads.forEach(function (overload: any) {
                        overload.implementation = function () {
                            let tid = Process.getCurrentThreadId();
                            let tname = Java.use("java.lang.Thread").currentThread().getName();
                            sendContent({
                                tid: tid,
                                status: 'entry',
                                tname: tname,
                                classname: clsname + '_$init',
                                method: overload.holder.toString(),
                                method_: overload._p[0],
                                args: arguments
                            });
                            const retval = this['$init'].apply(this, arguments);
                            sendContent({
                                tid: tid,
                                status: 'exit',
                                tname: tname,
                                classname: clsname,
                                method: overload.holder.toString(),
                                retval: retval
                            });
                            return retval;
                        }
                    });
                }
                catch (e) {
                }
            }
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

    export function toJSONString(obj: any) {
        if (null == obj) {
            return "obj is null";
        }
        let resstr = "";
        let GsonBuilder = null;
        try {
            GsonBuilder = Java.use('com.google.gson.GsonBuilder');
        }
        catch (e) {
            FCAnd.registGson();
            GsonBuilder = Java.use('com.google.gson.GsonBuilder');
        }
        if (null != GsonBuilder) {
            try {
                const gson = GsonBuilder.$new().serializeNulls()
                    .serializeSpecialFloatingPointValues()
                    .disableHtmlEscaping()
                    .setLenient()
                    .create();
                resstr = gson.toJson(obj);
            }
            catch (e: any) {
                DMLog.e('gson.toJson', 'exceipt: ' + e.toString());
                resstr = FCAnd.parseObject(obj);
            }
        }

        return resstr;
    }

    export function parseObject(data: any) {
        try {
            const declaredFields = data.class.getDeclaredFields();
            let res = {};
            for (let i = 0; i < declaredFields.length; i++) {
                const field = declaredFields[i];
                field.setAccessible(true);
                const type = field.getType();
                let fdata = field.get(data);
                if (null != fdata) {
                    if (type.getName() != "[B") {
                        fdata = fdata.toString();
                    }
                    else {
                        fdata = Java.array('byte', fdata);
                        fdata = JSON.stringify(fdata);
                    }
                }
                // @ts-ignore
                res[field.getName()] = fdata;
            }
            return JSON.stringify(res);
        }
        catch (e: any) {
            return "parseObject except: " + e.toString();
        }

    }


    export function registGson() {
        // const dexbase64 = gjson_dex;
        // DMLog.i('registGson', 'entry: ' + dexbase64.length);
        //
        // var application = Java.use("android.app.Application");
        // const bytes = new Buffer(dexbase64, 'base64');
        // const dexpath = application.$f.cacheDir + '/gson.jar';
        // const f = new File(dexpath, 'wb+');
        // f.write(bytes.buffer as ArrayBuffer);
        // f.flush()
        // f.close()
        try {
            let dexpath = '/data/local/tmp/fclibs/gson.jar';
            Java.openClassFile(dexpath).load();
        }
        catch (e) {
            DMLog.e('registGson', 'exception, please try to run `setupAndorid.py`')
        }

    }

    /**
     * 通过 DexClassLoader 加载的多 Dex，可用此方法按类名 use 并 callback 返回
     * @param clsname
     * @param callback 传回找到的类
     */
    export function useWithDexClassLoader(clsname: string, callback: (cls: Java.Wrapper) => void) {
        const tag = 'useWithDexClassLoader';
        var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
        //hook its constructor $init, we will print out its four parameters.
        dexclassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            DMLog.d(tag, "dexPath: " + dexPath);
            DMLog.d(tag, "optimizedDirectory: " + optimizedDirectory);
            DMLog.d(tag, "librarySearchPath: " + librarySearchPath);
            DMLog.d(tag, "parent: " + parent);
            //Without breaking its original logic, we call its original constructor.
            this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
            let cls = this.loadClass(clsname);
            if (null != cls) {
                DMLog.w('dex_loadclass', 'found: ' + clsname);
                callback(cls);
            }
        }
    }

    /**
     *
     * @param clsname   ex: org.chromium.base.PathUtils
     * @param callback
     */
    export function useWhenLoadClass(clsname: string, callback: (cls: Java.Wrapper) => void) {
        // java.lang.ClassLoader#loadClass(java.lang.String, boolean)
        const ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name: string) {
            // DMLog.i('loadClass', 'name: ' + name);
            const cls = this.loadClass(name);
            if (name.indexOf(clsname) > -1) {
                DMLog.w('useWhenLoadClass', `name: ${clsname} matched!`)
                try {
                    const clsFactory = Java.ClassFactory.get(this);
                    const useCls = clsFactory.use(clsname);
                    DMLog.e('loadClass', 'name: ' + name);
                    callback(useCls);
                }
                catch (e) {
                    DMLog.e('useWhenLoadClass', 'exception: ' + e);
                }
            }
            return cls;
        };
    }

    /**
     * 通过 InMemoryDexClassLoader 加载的多 Dex，可用此方法按类名 use 并 callback 返回
     * @param clsname
     * @param callback 传回找到的类
     */
    export function useWithInMemoryDexClassLoader(clsname: string, callback: (cls: Java.Wrapper) => void) {
        const tag = 'useWithInMemoryDexClassLoader';
        //  dalvik.system.InMemoryDexClassLoader
        try {
            const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
            InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                .implementation = function (buff, loader) {
                this.$init(buff, loader);
                let clsFactory = Java.ClassFactory.get(this);
                try {
                    let result = clsFactory.use(clsname);
                    DMLog.w(tag, JSON.stringify(result));
                    callback(result);
                }
                catch (e) {
                    DMLog.e(tag, `${clsname} not found: ${e}`);
                }
            }
        }
        catch (e: any) {
            DMLog.e(tag, e.toString());
        }

    }

    export function useWithBaseDexClassLoader(clsname: string, callback: (cls: Java.Wrapper) => void) {
        const tag = 'useWithBaseDexClassLoader';
        var dexclassLoader = Java.use("dalvik.system.BaseDexClassLoader");
        //hook its constructor $init, we will print out its four parameters.
        dexclassLoader.$init.overload('java.lang.String', 'java.io.File', 'java.lang.String', 'java.lang.ClassLoader')
            .implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            DMLog.d(tag, "dexPath: " + dexPath);
            DMLog.d(tag, "optimizedDirectory: " + optimizedDirectory);
            DMLog.d(tag, "librarySearchPath: " + librarySearchPath);
            DMLog.d(tag, "parent: " + parent);
            //Without breaking its original logic, we call its original constructor.
            this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
            let clsFactory = Java.ClassFactory.get(this);
            try {
                let result = clsFactory.use(clsname);
                DMLog.w(tag, JSON.stringify(result));
                callback(result);
            }
            catch (e) {
                DMLog.e(tag, `${clsname} not found: ${e}`);
            }
        }
    }

    export function showNativeStacks(context: any) {
        DMLog.i('showNativeStacks', '\tBacktrace:\n\t' + Thread.backtrace(context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
    }

    export function hook_send_recv() {
        // lets search for common shared lib
        var myModule = Process.getModuleByName('libc.so');
        var myFuncs = ['recv', 'send'];
        // var myFuncs = ['send'];

        // attach only to functions that have recv or send in name (includes recv, recvmsg, recvfrom, send ,sendmsg, sendto)
        myModule.enumerateExports().filter(module_export => module_export.type === 'function' &&
            myFuncs.some(fName => module_export.name.includes(fName)))
            .forEach(module_export => {
                Interceptor.attach(module_export.address, {
                    onEnter: function (args) { // every time we enter one of the functions, we will log this
                        const tag = module_export.name + "_onEnter";
                        //get function args
                        var fd = args[0].toInt32(); // every function has first argument an FD, so it is safe to do this

                        // error mitigation checks
                        // from frida.Socket (check if socket is TCP and if it has an external IP address)
                        var socktype = Socket.type(fd);
                        var sockaddr = Socket.peerAddress(fd);
                        if ((socktype !== 'tcp' && socktype !== 'tcp6') || sockaddr === null)
                            return;

                        try {
                            var len = args[2].toInt32();
                            this.buf = new NativePointer(args[1]);
                            var data = {
                                'event': module_export.name,
                                'fd': fd,
                                'sockaddr': sockaddr,
                                'socktype': socktype
                                // 'buffer': printByte2(buf2hex(buf))
                            }

                            DMLog.i(tag, '\n');
                            DMLog.i(tag, JSON.stringify(data));
                            FCAnd.showNativeStacks(this.context);
                        }
                        catch (err: any) {
                            DMLog.e(tag, err);
                        }
                    },
                    onLeave: function (retval) {
                        if (undefined != this.buf) {
                            const retlen = retval.toInt32();
                            DMLog.i(module_export.name + '_onLeave', "size:" + retval);
                            if (-1 != retlen) {
                                DMLog.i(module_export.name + '_onLeave', "\n" + hexdump(this.buf, {
                                    offset: 0,
                                    length: retlen,
                                    header: true,
                                    ansi: false
                                }));
                            }
                        }
                    }
                })
            });
    }

    /**
     * 搜索内存并替换目标值
     * @param addr      搜索起始地址
     * @param size      大小范围
     * @param pattern   FCCommon.str2hexstr("3C8F4F55D4B548E4EDBB1157EFAC3FC1")
     * @param distarr   替换数据，字符串可以用 FCCommon.str2hexArray("kkkkkkk")) 的返回值
     */
    export function replaceMemoryData(addr: NativePointer, size: number, pattern: string, distarr: ArrayBuffer | number[], replaceAll: boolean) {
        const tag = 'replaceMemoryData';
        let dest = Memory.scanSync(addr, size, pattern);
        if (null != dest && dest.length > 0) {
            DMLog.i(tag, 'found dest');
            if (replaceAll) {
                dest.forEach(function (match) {
                    match.address.writeByteArray(distarr);
                    DMLog.i(tag, "foreach replaced address: " + match.address);
                });
            }
            else {
                dest[0].address.writeByteArray(distarr);
                DMLog.i(tag, "replaced address: " + dest[0].address);
            }
        }
    }

    /**
     * 各种搜类，发现其是否能找到该类
     * 该方法通常用于启动时类的搜索
     * @param clsname
     */
    export function findClass(clsname: string) {
        FCAnd.useWhenLoadClass(clsname, function (cls) {
            DMLog.i('findclass useWhenLoadClass', "" + cls);
        });
        FCAnd.useWithDexClassLoader(clsname, function (cls) {
            DMLog.i('findclass useWithDexClassLoader', "" + cls);
        });
        FCAnd.useWithBaseDexClassLoader(clsname, function (cls) {
            DMLog.i('findclass useWithBaseDexClassLoader', "" + cls);
        });
        FCAnd.useWithInMemoryDexClassLoader(clsname, function (cls) {
            DMLog.i('findclass useWithInMemoryDexClassLoader', "" + cls);
        });
    }

    /**
     * 枚举 ClassLoader 找到相应的类，执行 callback
     * @param clsname
     * @param callback
     */
    export function enumerateClassLoadersAndUse(clsname: string, callback: (cls: Java.Wrapper) => void) {
        const tag = 'enumerateClassLoadersAndUse';
        enumerateClassLoadersAndGetFactory(clsname, function (cf) {
            try {
                let cls = cf.use(clsname);
                callback(cls);
            }
            catch (e: any) {
                DMLog.e(tag, `use ${clsname} excepted: ${e}`);
            }
        });
    }

    export function enumerateClassLoadersAndGetFactory(clsname: string, callback: (factory: Java.ClassFactory) => void) {
        const tag = 'enumerateClassLoadersAndGetFactory';
        Java.enumerateClassLoaders({
            onMatch(loader) {
                try {
                    let cls = loader.loadClass(clsname);
                    if (null != cls) {
                        DMLog.i(tag, "found cls: " + cls);

                        let cf = Java.ClassFactory.get(loader);
                        callback(cf);
                    }
                }
                catch (e: any) {
                    DMLog.w(tag, `classloader: ${loader} not found:${e.toString()}`);
                }
            },
            onComplete() {
                DMLog.i(tag, 'completed .');
            }
        });
    }

    /**
     * 当指定 so 加载时，进行 attach
     * @param soname
     * @param offsetAddr
     * @param callback
     */
    export function attachWhenSoLoad(soname: string, offsetAddr: number, callback: InvocationListenerCallbacks | InstructionProbeCallback) {
        whenSoLoad(soname, function (mod: Module) {
            Interceptor.attach(mod.base.add(offsetAddr), callback);
        });
    }

    export function whenSoLoad(soname: string, callback: (mod: Module) => void) {
        const VERSION = Java.use('android.os.Build$VERSION');
        let dlopenFuncName = "android_dlopen_ext";
        if (VERSION.SDK_INT.value <= 23) { // 6.0 以上版本
            dlopenFuncName = "dlopen";
        }
        var so_listener = Interceptor.attach(Module.findExportByName(null, dlopenFuncName) !, {
            onEnter: function (args) {
                this.sopath = args[0].readCString();
            },
            onLeave: function (retval) {
                let sopath = this.sopath;
                DMLog.d('WhenSoLoad dlopen', `sopath: ${sopath}`);
                if (null != sopath && sopath.indexOf(soname) > -1) {
                    let mod = Module.load(sopath);
                    callback(mod);
                    so_listener.detach();
                }
            }
        });
    }

    /**
     * 返回C++方法的 pretty name
     * 例如：_Z4hahaii -> haha(int, int)
     * let prettyname = FCAnd.prettyMethod_C("_Z4hahaii");
     * @param name
     */
    export function prettyMethod_C(name: string) {
        let ptr__cxa_demangle = Module.findExportByName("libc++.so", "__cxa_demangle");
        if (null == ptr__cxa_demangle) {
            DMLog.e("libc++.so", "__cxa_demangle not found");
            return;
        }
        let max_size = 0x200;
        let addr = Memory.alloc(max_size);
        let buffaddr = Memory.alloc(max_size);
        let buffsize = Memory.alloc(Process.pointerSize);
        let status = Memory.alloc(Process.pointerSize);

        addr.writeUtf8String(name);
        buffsize.writeUInt(max_size);
        status.writeUInt(0);
        let func_cxa_demangle = new NativeFunction(ptr__cxa_demangle, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
        func_cxa_demangle(addr, buffaddr, buffsize, status);
        let result = buffaddr.readCString();
        return result;
    }

    /**
     * 返回 Java 方法的 pretty name
     * ar classname = 'java/lang/String';
     * var env = Java.vm.getEnv();
     * var cla = env.findClass(classname);
     * DMLog.i("prettyMethod_Jni", "clazz:" + cla);
     * var methodId = env.getMethodId(cla, "toString", "()Ljava/lang/String;");
     * DMLog.i("prettyMethod_Jni", "methodId:" + methodId);
     * let ptyName = FCAnd.prettyMethod_Jni(methodId, 1);
     * DMLog.i("prettyMethod_Jni", "prettyMethod_Jni res: " + ptyName);
     * @param methodId
     * @param withSignature 1: 包含签名，0: 不包含签名
     */
    export function prettyMethod_Jni(methodId: any, withSignature: number) {
        let result = FCCommon.newStdString();
        // @ts-ignore
        Java.api['art::ArtMethod::PrettyMethod'](result, methodId, withSignature);
        return result.disposeToString();
    }

    /**
     * 获取进程名
     */
    export function getProcessName() {
        var openPtr = Module.getExportByName('libc.so', 'open');
        var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

        var readPtr = Module.getExportByName("libc.so", "read");
        var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

        var closePtr = Module.getExportByName('libc.so', 'close');
        var close = new NativeFunction(closePtr, 'int', ['int']);

        var path = Memory.allocUtf8String("/proc/self/cmdline");
        var fd = open(path, 0);
        if (fd != -1) {
            var buffer = Memory.alloc(0x1000);

            var readsize = read(fd, buffer, 0x1000);
            close(fd);
            let result = buffer.readCString();
            return result;
        }

        return null;
    }

    /**
     * 监听 svc 地址调用，并打印堆栈
     * @param base
     * @param address_list  需要配合 python/android/search_svc.py 脚本生成的地址列表，传入 address_list
     *                      例如：['0x4826c', '0x487bc', '0x48dc4', '0x496d4', '0x49880', '0x499d0']
     */
    export function watch_svc_address_list(base: NativePointer, address_list: string[]) {
        address_list.forEach((addr) => {
            let addr_offset = parseInt(addr, 16);
            Interceptor.attach(base.add(addr_offset), {
                onEnter: function (args) {
                    FCAnd.showNativeStacks(this.context);
                }
            });
        });
    }
}
