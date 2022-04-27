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
                        } catch (e : any) {
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
                } catch (e) {
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
        } catch (e) {
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
            } catch (e : any) {
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
        } catch (e : any) {
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
        } catch (e) {
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
                } catch (e) {
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
                } catch (e) {
                    DMLog.e(tag, `${clsname} not found: ${e}`);
                }
            }
        } catch (e : any) {
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
            } catch (e) {
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
                        } catch (err : any) {
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
        Java.enumerateClassLoaders({
            onMatch(loader) {
                try {
                    let cls = loader.loadClass(clsname);
                    if (null != cls) {
                        DMLog.i(tag, "found cls: " + cls);

                        let cf = Java.ClassFactory.get(loader);

                        let cls1 = cf.use(clsname);
                        callback(cls1);
                    }

                } catch (e : any) {
                    DMLog.e(tag, e.toString());
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
        Interceptor.attach(Module.findExportByName(null, dlopenFuncName) !, {
            onEnter: function (args) {
                this.sopath = args[0].readCString();
            },
            onLeave: function (retval) {
                let sopath = this.sopath;
                DMLog.d('WhenSoLoad dlopen', `sopath: ${sopath}`);
                if (null != sopath && sopath.indexOf(soname) > -1) {
                    let mod = Module.load(sopath);
                    callback(mod);
                }
            }
        });
    }
}
