/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: FCiOS.js
 * @time: 2020/9/16 12:39 PM
 * @desc:
 */
import {DMLog} from "./dmlog";
import {AntiIOS} from "./ios/AntiIOS";

export namespace FCiOS {

    export const anti = AntiIOS;

    export let nil = ObjC.available ? new ObjC.Object(ptr("0x0")) : null;

    // generic getFuncAddr
    export function getFuncAddr(pattern: string): NativePointer {
        var tag = 'getFuncAddr';
        let targets = FCiOS.findAllByPattern(pattern);
        var targetAddr = NULL;
        targets.forEach(function (target: any) {
            DMLog.d(tag, 'target.name: ' + target.name + ', target.address: ' + target.address);
            targetAddr = target.address;
            // end forEach
            return false;
        });

        return targetAddr;
    }

    /**
     * 模糊查找所有符合规则的函数
     * 示例参考: examples/ios_hook_all_base64.ts
     * @param pattern
     */
    export function findAllByPattern(pattern: string) {
        var tag = 'findAllByPattern';
        var type: ApiResolverType = (pattern.indexOf(" ") === -1) ? "module" : "objc";
        DMLog.d(tag, 'getFuncAddr type: ' + type);
        var res: ApiResolver = new ApiResolver(type);
        DMLog.d(tag, 'getFuncAddr ApiResolver: ' + JSON.stringify(res));
        var matches = res.enumerateMatches(pattern);
        DMLog.d(tag, 'getFuncAddr matches: ' + JSON.stringify(matches));
        var targets = uniqBy(matches, JSON.stringify);
        return targets;
    }

    // remove duplicates from array
    export function uniqBy(array: any, key: any) {
        var seen: any = {};
        return array.filter(function (item: any) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }

    export function showStacks(thiz: any) {
        DMLog.i('showStacks', '\tBacktrace:\n\t' + Thread.backtrace(thiz.context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
    }

    export function dump_ui() {
        try {
            var current_window = ObjC.classes.UIWindow.keyWindow();
            return current_window.recursiveDescription().toString();
        } catch (e) {
            return e;
        }

    }

    /**
     * trace openURL
     */
    export function trace_url() {
        //Twitter: https://twitter.com/xploresec
        //GitHub: https://github.com/interference-security
        // Get a reference to the openURL selector
        var openURL = ObjC.classes.UIApplication["- openURL:"];

        // Intercept the method
        Interceptor.attach(openURL.implementation, {
            onEnter: function (args) {
                // As this is an ObjectiveC method, the arguments are as follows:
                // 0. 'self'
                // 1. The selector (openURL:)
                // 2. The first argument to the openURL selector
                var myNSURL = new ObjC.Object(args[2]);
                // Convert it to a JS string
                var myJSURL = myNSURL.absoluteString().toString();
                // Log it
                DMLog.d('openURL', "Launching URL: " + myJSURL);
                //send(myJSURL);
            }
        });

    }

    export function trace_NSLog() {
        const NSLog_ptr = Module.findExportByName("Foundation", "NSLog");
        DMLog.i('NSLog_ptr', 'addr: ' + NSLog_ptr);
        if (NSLog_ptr) {
            Interceptor.attach(NSLog_ptr, {
                onEnter: function (args) {
                    DMLog.d('NSLog', new ObjC.Object(args[0]).toString());
                }
            });
        }

        const NSLogv_ptr = Module.findExportByName("Foundation", "NSLogv");
        DMLog.i('NSLogv_ptr', 'addr: ' + NSLogv_ptr);
        if (NSLogv_ptr) {
            Interceptor.attach(NSLogv_ptr, {
                onEnter: function (args) {
                    DMLog.d('NSLogv', new ObjC.Object(args[0]).toString());
                }
            });
        }
    }

    /**
     * var NSString = ObjC.use("NSString");
        var str = ObjC.cast(ptr("0x1234"), NSString);
     * -- or --
     * var str = ObjC.Object(ptr("0x1234"));
     * @param val
     */
    export function newString(val: any) {
        try {
            return ObjC.classes.NSString.stringWithString_(val);
        } catch (e) {
            return val;
        }
    }

    export function nsdataToString(nsdata: any) {
        return ObjC.classes.NSString.alloc().initWithData_encoding_(nsdata, 4);
    }

    export function getClassName(id: any) {
        return new ObjC.Object(id).$className;
    }

    export function printNSDictionary(id: any) {
        var dict = new ObjC.Object(id);
        var enumerator = dict.keyEnumerator();
        var key;
        while ((key = enumerator.nextObject()) !== null) {
            var value = dict.objectForKey_(key);
            DMLog.d('printNSDictionary', "key: " + key + ", val: " + value);
        }
    }

    export function justTouch(pattern: string) {
        let tgtarr;
        tgtarr = FCiOS.findAllByPattern(pattern);
        tgtarr.forEach(function (target: any) {
            DMLog.d('justTouch', `${target.name} attach ed`);
            Interceptor.attach(target.address, {
                onEnter: function (args) {
                    DMLog.d('justTouch', `==== name: ${target.name} onEnter ====`);
                }
            });
        });
    }
}