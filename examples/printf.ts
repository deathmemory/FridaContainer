import {FCAnd} from "../utils/FCAnd";

Java.perform(function() {
    console.log("[*] Frida Agent loaded. Hooking __log_print.");

    // 假设 __log_print 是从 liblog.so 或其他相关库导出的
    // 实际的库名可能需要根据你的目标来确定
    // 如果它在某个应用模块的PLT中，你需要先找到那个模块的导入
    // 这里我们假设它直接是liblog.so的导出函数
    const logPrintPtr = Module.findExportByName("liblog.so", "__log_print");

    if (logPrintPtr) {
        console.log(`[+] Found __log_print at: ${logPrintPtr}`);

        Interceptor.attach(logPrintPtr, {
            onEnter: function(args) {
                this.logLevel = args[0];     // 第一个参数: a1level
                this.logTagPtr = args[1];    // 第二个参数: a2title (char*)
                this.formatStringPtr = args[2]; // 第三个参数: a3format (const char*)

                // 尝试读取日志标签和格式字符串
                this.logTag = "(unknown)";
                if (this.logTagPtr.isValid()) {
                    try {
                        this.logTag = this.logTagPtr.readCString();
                    } catch (e) { /* ignore */ }
                }

                this.formatString = "(invalid format string)";
                if (this.formatStringPtr.isValid()) {
                    try {
                        this.formatString = this.formatStringPtr.readCString();
                    } catch (e) { /* ignore */ }
                }

                // 获取可变参数 (ARM64 约定)
                // 在 ARM64 上，前 8 个整数/指针参数通过 X0-X7 寄存器传递。
                // 如果格式字符串在 X2，那么后续参数从 X3 开始。
                // 浮点参数通过 D0-D7 寄存器传递。
                // 更多的参数在栈上。

                // 这是一个非常简化的处理，只假设后续参数也是指针或整数
                // 你需要根据实际的格式字符串和调用约定来精确解析
                // 对于 printf 风格的函数，解析可变参数是比较复杂的
                const varArgs = [];
                // 假设最多只取 5 个可变参数，且它们是64位整数或指针
                // 实际需要根据 __log_print 的具体用法和格式字符串来调整
                // X3, X4, X5, X6, X7 寄存器可能包含前几个 varargs
                let arm64Context = this.context as Arm64CpuContext;
                if (arm64Context.x3) varArgs.push(args[3]);
                if (arm64Context.x4) varArgs.push(args[4]);
                if (arm64Context.x5) varArgs.push(args[5]);
                if (arm64Context.x6) varArgs.push(args[6]);
                if (arm64Context.x7) varArgs.push(args[7]);

                // 如果还有更多参数，它们会通过栈传递
                // this.context.sp 是栈指针
                // readPointer(offset) 从栈上读取
                // 例如：this.context.sp.add(8).readPointer(); // 栈上第一个参数
                // 注意：读取栈上的参数时，需要考虑栈帧的布局和调用约定。

                // 尝试用自定义的 printf 模拟函数来拼装字符串
                // 这是一个简化版，对于复杂的格式化（如宽度、精度、长短整形等）可能不准确
                try {
                    this.parsedMessage = FCAnd.printf_native(this.formatString, ...varArgs);
                } catch (e: any) {
                    this.parsedMessage = `[Frida Parse Error] ${e.message} - Format: "${this.formatString}" - Args: ${varArgs.join(', ')}`;
                }

                console.log(`\n[__log_print HOOKED]`);
                console.log(`  Level: ${this.logLevel}`);
                console.log(`  Tag: "${this.logTag}"`);
                console.log(`  Original Format: "${this.formatString}"`);
                console.log(`  Parsed Message: "${this.parsedMessage}"`);
                console.log(`  Call Stack:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n")}`);
            },
        });

        console.log("[*] __log_print Hooked successfully!");
    } else {
        console.error("[-] Could not find __log_print. Make sure it's exported or correctly imported.");
    }
});