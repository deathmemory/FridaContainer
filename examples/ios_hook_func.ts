/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: ios_hook_func.js
 * @time: 2020/9/16 12:37 PM
 * @desc:
 */

import {FCiOS} from "../utils/FCiOS";
import {DMLog} from "../utils/dmlog";

if (ObjC.available) {
    const addr = FCiOS.getFuncAddr('*[NVEnvironment deviceId]');
    Interceptor.attach(addr, {
        onEnter: function (args) {

        },
        onLeave: function (retval) {
            retval.replace(ObjC.classes.NSString.stringWithString_('random_deviceidxxxxxxxxx'));
                // 87e041d4c2abb75fda2b2390474c993a70fcc0ff
                DMLog.d('deviceId', 'retval: ' + ObjC.classes.NSString.stringWithString_(retval));
        }
    })
}