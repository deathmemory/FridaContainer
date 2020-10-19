"use strict";
/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: StringUtils.js
 * @time: 2020/9/15 4:16 PM
 * @desc:
 */
Object.defineProperty(exports, "__esModule", { value: true });
class StringUtils {
    static randomHexStr(count) {
        return this.random(count, "1234567890ABCDEF");
    }
    static random(count, basestr) {
        var res = "";
        for (var i = 0; i < count; i++) {
            res += basestr.charAt(Math.floor(Math.random() * basestr.length));
        }
        return res;
    }
    static int2ip(ipInt, isHighEndian) {
        if (isHighEndian) {
            return ((ipInt >>> 24) + '.' + (ipInt >> 16 & 255) + '.' + (ipInt >> 8 & 255) + '.' + (ipInt & 255));
        }
        else {
            return ((ipInt & 255) + '.' + (ipInt >> 8 & 255) + '.' + (ipInt >> 16 & 255) + '.' + (ipInt >>> 24));
        }
    }
    static ip2int(ip, isHighEndian) {
        if (isHighEndian) {
            return ip.split('.').reduce(function (ipInt, octet) { return (ipInt << 8) + parseInt(octet, 10); }, 0) >>> 0;
        }
        else {
            return ip.split('.').reduce(function (ipInt, octet, idx) { return (parseInt(octet, 10) << idx * 8) + ipInt; }, 0) >>> 0;
        }
    }
}
exports.StringUtils = StringUtils;
