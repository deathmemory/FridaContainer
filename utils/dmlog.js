"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class DMLog {
    static d(tag, str) {
        DMLog.log_('DEBUG', tag, str);
    }
    static i(tag, str) {
        DMLog.log_('INFO', tag, str);
    }
    static e(tag, str) {
        DMLog.log_('ERROR', tag, str);
    }
    static log_(leval, tag, str) {
        console.log('[' + leval + '][' + new Date().toLocaleString('zh-CN') + '][' + tag + ']: ' + str);
    }
}
exports.DMLog = DMLog;
