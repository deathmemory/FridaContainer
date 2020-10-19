/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import {DMLog} from "./utils/dmlog";
import {FCCommon} from "./utils/FCCommon";

function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer, please add code on the index.ts');
    // FCAnd.Anti.anti_ptrace();
    // FCAnd.Anti.anti_fgets();
    // and.anti.Anti.anti_fgets();

    // FCAnd.anti.anti_debug();
    /// dp
    // DianPing.anti_debug();
    // DianPing.hook_cx_stacks();
    ///
    // FCAnd.AndOpts.showStacks();
    // FCAnd.AndOpts.dump_dex_common();
    // FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");
    FCCommon.trace_memoryAccess('Hopper Disassembler v4', 0x483959);
}

Java.perform(function () {
    main();
});
