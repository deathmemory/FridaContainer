/**
 * @author: dmemory
 * @contact: 
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import {DMLog} from "./utils/dmlog";
import {FCCommon} from "./utils/FCCommon";
import {FCAnd} from "./utils/FCAnd";
import Java from "frida-java-bridge"
import ObjC from "frida-objc-bridge"

function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer, please add code on the index.ts');

    // FCAnd.detect_anti_debug();
    // FCAnd.anti.anti_debug();
    // FCAnd.showStacks();
    // FCAnd.dump_dex_common();
    // FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");
    // coord: (0,203,25) | addr: Lcom.dianping.nvnetwork.tunnel.Encrypt.SocketSecureManager;->getB2keyByB2(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String; | loc: ?
    // FCAnd.traceArtMethods(['E:com.dianping.nvnetwork.tunnel.Encrypt.SocketSecureManager'], null, "122,108,111,103,46,98,105,110");  // "zlog.bin"
    // FCAnd.anti.anti_ssl_unpinning();
    // FCAnd.hook_uri(true);
    // FCAnd.hook_url(true);
    // FCAnd.jni.traceAllJNISimply();
    // FCAnd.traceArtMethods(['M:retrofit2']);
    // rpc.exports = {
    //     test() {
    //         Java.perform(() => {
    //             FCAnd.jni.traceAllJNISimply();
    //         });
    //     }
    // }
}

if (Java.available) {
    DMLog.i("JAVA", "available");
    Java.perform(function () {
        main();
    });
}

// 将 FCAnd 挂载到 global 上，使它可以在 Frida REPL 中作为全局对象访问
// @ts-ignore
// global.fcrepl_android = {
//     touchAddress: function (libname: string, addresses: number[]) {
//         let mod = Process.getModuleByName(libname);
//         for (let i = 0; i < addresses.length; i++) {
//             let addr = mod.base.add(addresses[i]);
//             Interceptor.attach(addr, {
//                 onEnter: function (args) {
//                     DMLog.i("fcrepl", "Touch: " + libname + " " + addresses[i].toString(16));
//                     FCAnd.showAllStacks(this.context);
//                 }
//             });
//         }
//     },
//     hexdump: function (address: number) {
//         DMLog.i("hexdump", hexdump(ptr(address)));
//     }
// };

if (ObjC.available) {
    DMLog.i("ObjC", "available");
    FCCommon.printModules();
    FCCommon.dump_module("Hopper Disassembler v4", "/Users/dmemory/Downloads/");
}


