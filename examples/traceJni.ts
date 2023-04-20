import {FCAnd} from "../utils/FCAnd";

/**
 * trace jni 两种用法
 * 结合 `python/android/traceLogCleaner.py` 使用效果更佳
 */
if (Java.available) {
    Java.perform(function () {
        // 直接 trace 所有 Jni 函数
        FCAnd.jni.traceAllJNISimply();

        // 只 trace 指定的 jni 函数
        FCAnd.jni.traceJNI(['CallStaticObjectMethod', 'CallObjectMethod']);
    });
}
