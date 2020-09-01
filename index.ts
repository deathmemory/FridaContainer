/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */

import {DMLog} from "./utils/dmlog";

function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer');
    // FCAnd.AndOpts.getLR(null);
    // FCAnd.Anti.anti_ptrace();
    // FCAnd.Anti.anti_fgets();
    // and.anti.Anti.anti_fgets();

    FCAnd.Anti.anti_fgets();
    FCAnd.AndOpts.showStacks();
    FCAnd.AndOpts.dump_dex_common();
    FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");
}

Java.perform(function () {
    main();
});
