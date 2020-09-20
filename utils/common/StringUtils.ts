/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: StringUtils.js
 * @time: 2020/9/15 4:16 PM
 * @desc:
 */

export class StringUtils {

    static randomHexStr(count: number) {
        return this.random(count, "1234567890ABCDEF");
    }

    static random(count: number, basestr: string) {
        var res = "";
        for (var i = 0; i < count; i++) {
            res += basestr.charAt(Math.floor(Math.random() * basestr.length));
        }
        return res;
    }
}