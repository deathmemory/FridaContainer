export class DMLog {
    static bDebug: boolean = true;

    static d(tag: string, str: string) {
        if (this.bDebug) {
            DMLog.log_(console.log, 'DEBUG', tag, str);
        }
    }

    static i(tag: string, str: string) {
        DMLog.log_(console.log, 'INFO', tag, str);
    }

    static w(tag: string, str: string) {
        DMLog.log_(console.warn, 'WARN', tag, str);
    }

    static e(tag: string, str: string) {
        DMLog.log_(console.error, 'ERROR', tag, str);
    }

    static log_(logfunc: (message?: any, ...optionalParams: any[]) => void, leval: string, tag: string, str: string) {
        let threadName = "";
        if (Java.available) {
            Java.perform(() => {
                const Thread = Java.use('java.lang.Thread');
                threadName = `[${Thread.currentThread().getName()}]`;
            });
        }
        logfunc(`[${leval}][${new Date().toLocaleString('zh-CN')}][PID:${Process.id}]${threadName}[${Process.getCurrentThreadId()}][${tag}]: ${str}`);
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