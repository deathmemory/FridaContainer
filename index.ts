/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import {DMLog} from "./utils/dmlog";
import {FCAnd} from "./utils/FCAnd";
import {MT} from "./agent/mt/mt";
import {DianPing} from "./agent/dp/dp";

function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer');
    // FCAnd.AndOpts.getLR(null);
    // FCAnd.Anti.anti_ptrace();
    // FCAnd.Anti.anti_fgets();
    // and.anti.Anti.anti_fgets();

    // FCAnd.anti.anti_debug();
    /// mt
    // DianPing.anti_debug();
    // DianPing.hook_cx_stacks();
    DianPing.modify_devinfo();
    ///
    // FCAnd.AndOpts.showStacks();
    // FCAnd.AndOpts.dump_dex_common();
    // FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");
}

Java.perform(function () {
    main();
});
