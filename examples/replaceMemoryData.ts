/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: replaceMemoryData.js
 * @time: 2021/8/26 2:34 下午
 * @desc: 内存数据替换
 */

import {DMLog} from "../utils/dmlog";
import {FCAnd} from "../utils/FCAnd";
import {FCCommon} from "../utils/FCCommon";

rpc.exports = {
    ms() {
        // 写入测试数据
        let am = Memory.alloc(0x60);
        DMLog.i('fc', 'alloc: ' + am);
        am.writeByteArray([0, 1, 2, 3, 4]);
        am.add(5).writeUtf8String("3C8F4F55D4B548E4EDBB1157EFAC3FC1");
        am.add(40).writeUtf8String("3C8F4F55D4B548E4EDBB1157EFAC3FC1");
        DMLog.i('fc', hexdump(am));
        // 替换数据
        FCAnd.replaceMemoryData(am, 0x60,
            FCCommon.str2hexstr("3C8F4F55D4B548E4EDBB1157EFAC3FC1"),
            FCCommon.str2hexArray("kkkkkkk"), false);
        // 验证数据
        DMLog.i('fc after', hexdump(am));
        let tgtarr = am.add(5).readByteArray(32);
    }
}