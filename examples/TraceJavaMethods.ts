/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: TraceJavaMethods.js
 * @time: 2020/12/10 11:00 上午
 * @desc: trace java methods example
 *          建议从 python/android/traceLogCleaner.py 启动，
 *          默认 attach 当前打开的应用，并将日志格式化输出到当前目录的 tdc_dir 文件夹中
 *          方便搜索
 */

import {FCAnd} from "../utils/FCAnd";

if (Java.available) {
    Java.perform(() => {
        // [1] trace by default value
        FCAnd.traceJavaMethods();
        // [2] trace art 作为别称使用
        FCAnd.traceArtMethods();
        // [3] trace custom methods
        FCAnd.traceJavaMethods(
            ['M:MainActivity', 'E:java.lang.String'],
            {'java.lang.String': {white: true, methods: ['substring', 'getChars']}},
            "match_str_show_stacks"
        );
        // [4] trace custom methods without defaults, you need to do it yourself
        FCAnd.traceJavaMethods_custom(
            FCAnd.tjm_default_cls,
            FCAnd.tjm_default_white_detail,
            "match_str_show_stacks"
        );
        // [5] trace java constructors
        FCAnd.traceJavaMethods_custom(['E:java.net.URI'],
            {'java.net.URI': {white: true, methods: ['$init']}},
            "match_str_show_stacks");
    });
}
