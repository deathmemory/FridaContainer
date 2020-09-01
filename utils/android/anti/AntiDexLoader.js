/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */

function anti_InMemoryDexClassLoader(callbackfunc) {
    //  dalvik.system.InMemoryDexClassLoader
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
        .implementation = function (buff, loader) {
        this.$init(buff, loader);
        var oldcl = Java.classFactory.loader;
        Java.classFactory.loader = this;
        callbackfunc();
        Java.classFactory.loader = oldcl;

        return undefined;
    }
}

exports.anti_InMemoryDexClassLoader = anti_InMemoryDexClassLoader;
