import {FCAnd} from "../utils/FCAnd";

/**
 * 启动完成后，调用 rpc.exports.ddc() 完成 dump dex
 */

if (Java.available) {
    Java.perform(() => {
        FCAnd.dump_dex_loadAllClass();
    });
}
