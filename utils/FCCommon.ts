import {DMLog} from "./dmlog";
import {StdString} from "./StdString";

/**
 * @author: dmemory
 * @contact:
 * @file: FCCommon.js
 * @time: 2020/10/13 3:23 PM
 * @desc: 跨平台可通用的方法
 */

export namespace FCCommon {

    export var NOP_ARM64: number[] = [0x1F, 0x20, 0x03, 0xD5];

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

    export function getLrModuleDesc(context: CpuContext) {
        let lr = FCCommon.getLR(context);
        var module = Process.findModuleByAddress(lr);
        if (module) {
            return `${module.name}!${lr.sub(module.base)}`;
        }
        else {
            return `${lr}`;
        }
    }


    export function findExportByName(moduleName: string, exportName: string) {
        let module = Process.findModuleByName(moduleName);
        if  (module) {
            return module.findExportByName(exportName);
        }
        return null;
    }

    export function getExportByName(moduleName: string, exportName: string) {
        let module = Process.getModuleByName(moduleName);
        return module.getExportByName(exportName);
    };

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
        }
        catch (e) {
            const fopen_ptr = Module.getGlobalExportByName('fopen');
            const fwrite_ptr = Module.getGlobalExportByName('fwrite');
            const fclose_ptr = Module.getGlobalExportByName('fclose');
            if (fopen_ptr && fwrite_ptr && fclose_ptr) {
                const fopen_func = new NativeFunction(fopen_ptr, 'pointer', ['pointer', 'pointer']);
                const fwrite_func = new NativeFunction(fwrite_ptr, 'int', ['pointer', 'int', 'int', 'pointer']);
                const fclose_func = new NativeFunction(fclose_ptr, 'int', ['pointer']);

                let savePath_ptr = Memory.alloc(savePath.length + 1);
                savePath_ptr.writeUtf8String(savePath);
                const f = fopen_func(savePath_ptr, Memory.alloc(3).writeUtf8String("wb"));
                DMLog.i(tag, 'fopen: ' + f);
                if (f != null && readed) {
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

    export function dump2file(addr: NativePointer, size: number, savePath: string) {
        DMLog.i('dump2file', `addr: ${addr.toString(16)}, size: ${size}`);
        let file = new File(savePath, "w+");
        let byteArr = addr.readByteArray(size);
        if (null != byteArr) {
            file.write(byteArr);
        }
        file.close();
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

    /**
     * stalker trace 功能
     * 由于函数内使用 Stalker.exclude 每次使用建议重启进程，否则可能会有莫名其妙的段、访问错误
     * @param moduleName 模块(so) 名称
     * @param address 要监控的函数地址
     *
     * 用例 FCCommon.stalkerTrace("libxxx.so", addr_2333F);
     */
    export function stalkerTrace(moduleName: string, address: NativePointer) {
        const tag = 'stalkerTrace';
        let module_object = Process.findModuleByName(moduleName);
        if (null == module_object) {
            DMLog.e(tag, "module is null");
            return;
        }
        const module_start = module_object.base;
        const module_end = module_object.base.add(module_object.size);
        // 开始 trace
        let pre_regs = {};
        // let address = module_object.base.add(offset_address);
        // 排除不需要trace 的模块
        Process.enumerateModules().forEach(function (md) {
            if (md.name != moduleName) {
                let memoryRange = {base: md.base, size: md.size};
                Stalker.exclude(memoryRange);
            }
        });
        let threadId = Process.getCurrentThreadId();
        Interceptor.attach(address, {
            onEnter: function (args) {
                this.tid = threadId;
                if (threadId == this.threadId) {
                    this.startFollow = true;
                    Stalker.follow(this.tid, {
                        events: {
                            call: true,
                            ret: false,
                            exec: true,
                            block: false,
                            compile: false
                        },
                        transform(iterator: any) {
                            let instruction = iterator.next();
                            do {
                                const startAddress = instruction.address;
                                const isModuleCode = startAddress.compare(module_start) >= 0 && startAddress.compare(module_end) === -1;
                                if (isModuleCode) {
                                    iterator.putCallout(function (context: any) {
                                        let pc = context.pc;
                                        let module = Process.findModuleByAddress(pc);
                                        if (module) {
                                            try {
                                                let diff_regs = get_diff_regs(context, pre_regs);
                                                if (module.name == module_object?.name) {
                                                    DMLog.i(tag, `${module.name} ! ${pc.sub(module.base)} ${Instruction.parse(pc)} ${JSON.stringify(diff_regs)}`);
                                                    // console.log(module.name + " ! " + pc.sub(module.base), Instruction.parse(ptr(pc)), JSON.stringify(diff_regs));
                                                }
                                            }
                                            catch (e: any) {
                                                DMLog.e(tag, e.toString());
                                            }
                                        }
                                    })
                                }
                                iterator.keep();
                            } while ((instruction = iterator.next()) != null);
                        }
                    });
                }
            },
            onLeave: function (retval) {
                if (this.startFollow != undefined && this.startFollow == true) {
                    Stalker.unfollow(this.tid);
                    this.startFollow = false;
                }
            }
        });
    }

    export function get_diff_regs(context: any, pre_regs: any) {
        var diff_regs = {};
        for (const [reg_name, reg_value] of
            Object.entries(JSON.parse(JSON.stringify(context)))) {
            if (reg_name != "pc" && pre_regs[reg_name] !== reg_value) {
                pre_regs[reg_name] = reg_value;
                // @ts-ignore
                diff_regs[reg_name] = reg_value;
            }
        }
        return diff_regs;
    }

    export function newStdString() {
        return new StdString();
    }

    // 定义复制文件的函数
    export function copyFile(srcPath: string, dstPath: string) {
        let tmp = File.readAllBytes(srcPath);
        File.writeAllBytes(dstPath, tmp);
    }

    export function patchCode(addr: any, patchCode: any[]) {
        // 修改内存权限
        const pageSize = Process.pageSize;
        const pageBase = addr.and(ptr((1 << pageSize) - 1).not());
        Memory.protect(pageBase, pageSize, 'rwx');

        // 写入 NOP
        addr.writeByteArray(patchCode);
        DMLog.d("check_addr", `patch applied at address: ${addr}`);
    }

    /**
     * malloc
     * 解析一下为什么需要封装一下原生调用 malloc 的方法，而不使用 frida 的 Memory.alloc()
     * 因为 Memory.alloc() 是固定在 frida 私有空间地址下申请堆空间，
     * 在一些特殊场景下，系统会识别内存地址的范围，会导致 frida 的空间地址范围无法被系统使用，比如：
     * frida 申请空间为：0x76f4403b00
     * 系统识别内存地址是：0xb400007773886820
     * 这里检查了 0xb4... 的内存地址范围，所以需要使用原生的 malloc() 方法，保证了地址在正常范围之内。
     *
     * 系统/内核 API 的内存验证与安全边界 (System/Kernel API Memory Validation and Security Boundaries)
     * 这是问题的核心。 当应用程序通过系统调用（如 openat、read、write 等）将一个内存指针（例如缓冲区地址）传递给内核，
     * 或者传递给系统内部的核心库（例如 Native 服务、驱动程序）时，这些底层组件会对其进行严格的验证。
     * 当 0x76f... 这个由 Frida 自身分配的地址被传递给一个系统 API 时，该 API 内部的验证逻辑会判断这个地址不属于它所期望的
     * “合法”或“标准”的用户空间内存范围，或者不具备特定的权限或来源标记。
     *
     * 因此，系统会拒绝使用这个内存地址，表现为函数返回错误（例如 EFAULT 或其他错误码），
     * 甚至可能触发进程崩溃（例如 SIGSEGV 或 SIGABRT），以防止潜在的安全漏洞或不一致性。
     * 而 0xb40000... 可能就是系统或应用正常堆分配所在的一个典型地址范围。
     * @param number
     */
    export function malloc(number: number) {
        let mallocPtr = Module.getGlobalExportByName("malloc");
        if (mallocPtr) {
            let size = 0x100;
            let malloc = new NativeFunction(mallocPtr, "pointer", ["size_t"]);
            let buffer = malloc(size);
            if (buffer.isNull()) {
                DMLog.e("malloc", "malloc failed");
                return null;
            }
            return buffer;
        }
        return null;
    }

}

