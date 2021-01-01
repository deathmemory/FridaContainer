/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: method_data.js
 * @time: 2020/12/22 8:51 下午
 * @desc:
 */
import {FCCommon} from "../../FCCommon";

class BacktraceJSONContainer {
    public readonly address: NativePointer;

    public readonly module: Module | null;

    // public readonly symbol: DebugSymbol | null;

    public constructor (
        address: NativePointer,
        module: Module | null,
        // symbol: DebugSymbol | null
    ) {
        this.address = address;
        this.module = module;
        // this.symbol = symbol;
    }
}

export class MethodData {
    private tag = 'MethodData';
    private methodname: string;
    private args: InvocationArguments;
    private retval?: InvocationReturnValue;
    private methodDef: any;
    private jnival: { args: any[]; ret: any };
    private backtrace: BacktraceJSONContainer[];

    public constructor(ctx: CpuContext, methodname: string, methodDef: any, args: InvocationArguments, retval?: InvocationReturnValue) {
        this.methodname = methodname;
        this.methodDef = methodDef;
        this.args = args;
        this.jnival = {'args': [], 'ret': null};
        // let bt = Thread.backtrace(ctx, Backtracer.ACCURATE); //  Backtracer.FUZZY
        // this.backtrace = bt.map((addr: NativePointer): BacktraceJSONContainer => {
        //     return new BacktraceJSONContainer(
        //         addr,
        //         Process.findModuleByAddress(addr),
        //         DebugSymbol.fromAddress(addr)
        //     );
        // });
        let addr = FCCommon.getLR(ctx);
        if (ptr(0) != addr) {
            this.backtrace = [new BacktraceJSONContainer(addr, Process.findModuleByAddress(addr))];
        }
        else {
            this.backtrace = [];
        }

        let argTypes = this.methodDef.args as any[];
        for (let i = 0; i < argTypes.length; i++) {
            let ptr = args[i];
            let argType = argTypes[i];
            let argval = MethodData.getFridaValue(argType, ptr);
            this.jnival.args.push({argType: argType, argVal: argval});
        }

        if (null != retval) {
            this.setRetval(retval);
        }
    }

    public setRetval(retval: InvocationReturnValue) {
        this.retval = retval;
        let retType = this.methodDef.ret;
        let retVal = MethodData.getFridaValue(this.methodDef.ret, retval);
        this.jnival.ret = {retType: retType, retVal: retVal};
    }

    public toString(): string {
        return JSON.stringify(this);
    }

    static getFridaValue(type: string, ptr: NativePointer) {
        if (null == ptr || 0 == ptr.toInt32()) {
            return ptr;
        }
        if (type.endsWith('*')) {
            if (type.startsWith('char')) {
                return ptr.readCString();
            }
            else if (type.startsWith('jchar')) {
                let res = null;
                try {
                    let tmp = ptr.readUtf16String();
                    if (tmp) {
                        if (tmp[0].charCodeAt(0) < 0x80) {
                            for (let i = 0; i < tmp.length; ++i) {
                                if (tmp.charCodeAt(i) > 0x80) {
                                    tmp = tmp.substring(0, i);
                                    break;
                                }
                            }
                        }
                        if (tmp.length < 2) {
                            tmp += "(hex:0x" + ptr.readU16().toString(16) + ")";
                        }
                    }
                    res = tmp;
                } catch (e) {
                }
                return res == null ? "" : res;
            }
            else {
                try {
                    return ptr.readPointer();
                } catch (e) {
                    return ptr;
                }
            }
        }
        else {
            if ('jstring' === type) {
                return Java.vm.getEnv().stringFromJni(ptr);
            }
            else if ('jclass' === type) {
                return Java.vm.getEnv().getClassName(ptr);
            }
            return ptr;
        }
    }
}