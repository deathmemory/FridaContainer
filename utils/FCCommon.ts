import {DMLog} from "./dmlog";

/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: FCCommon.js
 * @time: 2020/10/13 3:23 PM
 * @desc: 跨平台可通用的方法
 */

export namespace FCCommon {

    /**
     * 打印指定层数的 sp，并输出 module 信息 (如果有）
     * @param {CpuContext} context
     * @param {number} number
     */
    export function showStacksModInfo(context: CpuContext, number: number) {
        var sp: NativePointer = context.sp;

        for (var i = 0; i < number; i++) {
            var curSp = sp.add(Process.pointerSize * i);
            DMLog.i('showStacksModInfo', 'curSp: ' + curSp + ', val: ' + curSp.readPointer()
                + ', module: ' + FCCommon.getModuleByAddr(curSp.readPointer()));
        }
    }


    /**
     * 根据地址获取模块信息
     * @param {NativePointer} addr
     * @returns {string}
     */
    export function getModuleByAddr(addr: NativePointer): Module | null {
        var result = null;
        Process.enumerateModules().forEach(function (module: Module) {
            if (module.base <= addr && addr <= (module.base.add(module.size))) {
                result = JSON.stringify(module);
                return false; // 跳出循环
            }
        });
        return result;
    }


    /**
     * 获取 LR 寄存器值
     * @param {CpuContext} context
     * @returns {NativePointer}
     */
    export function getLR(context: CpuContext) {
        if (Process.arch == 'arm') {
            return (context as ArmCpuContext).lr;
        }
        else if (Process.arch == 'arm64') {
            return (context as Arm64CpuContext).lr;
        }
        else {
            DMLog.e('getLR', 'not support current arch: ' + Process.arch);
        }
        return ptr(0);
    }

    /**
     * dump 指定模块并存储到指定目录
     * @param {string} moduleName
     * @param {string} saveDir      如果 Android 环境下应该保存在 /data/data/com.package.name/ 目录下，
     *                              否则可能会遇到权限问题，导致保存失败。
     */
    export function dump_module(moduleName: string, saveDir: string) {
        const tag = 'dump_module';
        const module = Process.getModuleByName(moduleName);
        const base = module.base;
        const size = module.size;
        const savePath: string = saveDir + "/" + moduleName + "_" + base + "_" + size + ".fcdump";
        DMLog.i(tag, "base: " + base + ", size: " + size);
        DMLog.i(tag, "save path: " + savePath);
        Memory.protect(base, size, "rwx");
        
        let readed = base.readByteArray(size);
        try {
            const f = new File(savePath, "wb");
            if (f) {
                if (readed) {
                    f.write(readed);
                    f.flush();
                }
                f.close();
            }
        } catch (e) {
            const fopen_ptr = Module.getExportByName(null, 'fopen');
            const fwrite_ptr = Module.getExportByName(null, 'fwrite');
            const fclose_ptr = Module.getExportByName(null, 'fclose');
            if (fopen_ptr && fwrite_ptr && fclose_ptr) {
                const fopen_func = new NativeFunction(fopen_ptr, 'pointer', ['pointer', 'pointer']);
                const fwrite_func = new NativeFunction(fwrite_ptr, 'int', ['pointer', 'int', 'int', 'pointer']);
                const fclose_func = new NativeFunction(fclose_ptr, 'int', ['pointer']);

                let savePath_ptr = Memory.alloc(savePath.length + 1);
                savePath_ptr.writeUtf8String(savePath);
                const f = fopen_func(savePath_ptr, Memory.alloc(3).writeUtf8String("wb"));
                DMLog.i(tag, 'fopen: ' + f);
                if (f != 0 && readed) {
                    const readed_ptr = Memory.alloc(readed.byteLength);
                    readed_ptr.writeByteArray(readed);
                    fwrite_func(readed_ptr, readed.byteLength, 1, f);
                    fclose_func(f);
                }
                else {
                    DMLog.e(tag, 'failed: f->' + f + ', readed->' + readed);
                }
            }
        }
    }

    export function printModules() {
        Process.enumerateModules().forEach(function (module) {
            DMLog.i('enumerateModules', JSON.stringify(module));
        });
    }

    export function str2hexstr(str: string) {
        let res = str.split("").map(x => x.charCodeAt(0).toString(16).padStart(2, "0")).join("");
        return res;
    }

    export function str2hexArray(str: string) {
        return str.split("").map(x => x.charCodeAt(0));
    }

    export function arrayBuffer2Hex(buf: any) {
        return [...new Uint8Array(buf)]
              .map(x => x.toString(16).padStart(2, '0'))
              .join(' ');
    }
}