"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const dmlog_1 = require("./dmlog");
/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: FCCommon.js
 * @time: 2020/10/13 3:23 PM
 * @desc: 跨平台可通用的方法
 */
class FCCommon {
    /**
     * 打印指定层数的 sp，并输出 module 信息 (如果有）
     * @param {CpuContext} context
     * @param {number} number
     */
    static showStacksModInfo(context, number) {
        var sp;
        if (Process.arch == 'arm') {
            sp = context.sp;
        }
        else if (Process.arch == 'arm64') {
            sp = context.sp;
        }
        else {
            return;
        }
        for (var i = 0; i < number; i++) {
            var curSp = sp.add(Process.pointerSize * i);
            dmlog_1.DMLog.i('And showStacksModInfo', 'curSp: ' + curSp + ', val: ' + curSp.readPointer()
                + ', module: ' + FCCommon.getModuleByAddr(curSp.readPointer()));
        }
    }
    /**
     * 根据地址获取模块信息
     * @param {NativePointer} addr
     * @returns {string}
     */
    static getModuleByAddr(addr) {
        var result = null;
        Process.enumerateModules().forEach(function (module) {
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
    static getLR(context) {
        if (Process.arch == 'arm') {
            return context.lr;
        }
        else if (Process.arch == 'arm64') {
            return context.lr;
        }
        return ptr(0);
    }
    static trace_open() {
        const open_ptr = Module.findExportByName(null, "open");
        if (open_ptr) {
            Interceptor.attach(open_ptr, {
                onEnter: function (args) {
                    dmlog_1.DMLog.i('trace_open', 'filepath: ' + args[0].readCString());
                }
            });
        }
    }
    static trace_memoryAccess(moduleName, offset) {
        const tag = 'trace_memoryAccess';
        const moduleBase = Module.findBaseAddress(moduleName);
        var absAddr;
        if (null != moduleBase) {
            absAddr = moduleBase.add(offset);
        }
        else {
            absAddr = new NativePointer(offset);
        }
        Memory.protect(absAddr, Process.pointerSize, '---');
        dmlog_1.DMLog.i(tag, 'final mem access addr: ' + absAddr);
        Process.setExceptionHandler(function (details) {
            var memory = details["memory"];
            if (memory) {
                var except_address = memory["address"];
                dmlog_1.DMLog.i(tag, "except_address: " + except_address);
                if (except_address == absAddr) {
                    dmlog_1.DMLog.i(tag, 'except address matched');
                    dmlog_1.DMLog.i(tag, JSON.stringify(details));
                }
            }
        });
    }
}
exports.FCCommon = FCCommon;
