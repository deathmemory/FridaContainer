import {FCiOS} from "../utils/FCiOS";
import {DMLog} from "../utils/dmlog";

if (ObjC.available) {
    const targets = FCiOS.findAllByPattern('*[* base64EncodedDataWithOptions*]');
    targets.forEach(function (target: any) {
        DMLog.i('base64EncodedDataWithOptions', 'target.name: ' + target.name + ', target.address: ' + target.address);
        Interceptor.attach(target.address, {
            onEnter: function (args) {
                FCiOS.showStacks(this);
            },
            onLeave: function (retval) {
                DMLog.i('base64EncodedDataWithOptions', 'retval: ' + FCiOS.nsdataToString(retval));
            }
        })
    });
}