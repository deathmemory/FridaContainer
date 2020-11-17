/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: android_dump_module.js
 * @time: 2020/11/12 8:29 下午
 * @desc:
 */

import {FCCommon} from "../utils/FCCommon";

if (Java.available) {
    Java.perform(() => {
        FCCommon.dump_module('libmtguard.so', '/data/data/com.dianping.v1');
    });
}

if (ObjC.available) {
    FCCommon.dump_module('Hopper Disassembler v4', "./");
}
