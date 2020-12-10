/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: TraceArtMethods.js
 * @time: 2020/12/10 11:00 上午
 * @desc:
 */

import {FCAnd} from "../utils/FCAnd";

if (Java.available) {
    Java.perform(() => {
        // [1] trace by default value
        FCAnd.andOpts.traceArtMethods();
        // [2] trace custom methods
        FCAnd.andOpts.traceArtMethods(
            ['M:MainActivity', 'E:java.lang.String'],
            {'java.lang.String': {white: true, methods:['substring', 'getChars']} }
        );
    });
}
