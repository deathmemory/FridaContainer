export class DMLog {
    static d(tag: String, str: String) {
        DMLog.log_('DEBUG', tag, str);
    }

    static i(tag: String, str: String) {
        DMLog.log_('INFO', tag, str);
    }

    static e(tag: String, str: String) {
        DMLog.log_('ERROR', tag, str);
    }

    static log_(leval: String, tag: String, str: String) {
        console.log('[' + leval + '][' + tag + ']: ' + str);
    }
}