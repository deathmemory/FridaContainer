import {FCAnd} from "../utils/FCAnd";

/**
 * chrome cronet bypass 使用示例。
 */
if (Java.available) {
    Java.perform(() => {
        FCAnd.afterSoLoad("libsscronet.so", mod => {
            FCAnd.anti.anti_ssl_cronet_32();
        });
    });
}
