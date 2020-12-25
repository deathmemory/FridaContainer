export class DMLog {
    private static bDebug: boolean = true;

    static d(tag: string, str: string) {
        if (this.bDebug) {
            DMLog.log_('DEBUG', tag, str);
        }
    }

    static i(tag: string, str: string) {
        DMLog.log_('INFO', tag, str);
    }

    static e(tag: string, str: string) {
        DMLog.log_('ERROR', tag, str);
    }

    static log_(leval: string, tag: string, str: string) {
        console.log('[' + leval + '][' + new Date().toLocaleString('zh-CN') + '][' + tag + ']: ' + str);
    }

    static send(tag: string, content: string) {
        let tid = Process.getCurrentThreadId();
        send(JSON.stringify({
            tid: tid,
            status: 'msg',
            tag: tag,
            content: content
        }));
    }
}