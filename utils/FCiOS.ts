/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: FCiOS.js
 * @time: 2020/9/16 12:39 PM
 * @desc:
 */
import {DMLog} from "./dmlog";

export namespace FCiOS {
    // generic getFuncAddr
    export function getFuncAddr(pattern: string): NativePointer {
        var tag = 'getFuncAddr';
        var type: ApiResolverType = (pattern.indexOf(" ") === -1) ? "module" : "objc";
        DMLog.i(tag, 'getFuncAddr type: ' + type);
        var res: ApiResolver = new ApiResolver(type);
        DMLog.i(tag, 'getFuncAddr ApiResolver: ' + JSON.stringify(res));
        var matches = res.enumerateMatches(pattern);
        DMLog.i(tag, 'getFuncAddr matches: ' + JSON.stringify(matches));
        var targets = uniqBy(matches, JSON.stringify);

        var targetAddr = NULL;
        targets.forEach(function (target: any) {
            DMLog.i(tag, 'target.name: ' + target.name + ', target.address: ' + target.address);
            targetAddr = target.address;
            // end forEach
            return false;
        });

        return targetAddr;
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
        }
        catch (e) {
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
                DMLog.i('openURL', "Launching URL: " + myJSURL);
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
                    DMLog.i('NSLog', new ObjC.Object(args[0]).toString());
                }
            });
        }

        const NSLogv_ptr = Module.findExportByName("Foundation", "NSLogv");
        DMLog.i('NSLogv_ptr', 'addr: ' + NSLogv_ptr);
        if (NSLogv_ptr) {
            Interceptor.attach(NSLogv_ptr, {
                onEnter: function (args) {
                    DMLog.i('NSLogv', new ObjC.Object(args[0]).toString());
                }
            });
        }
    }
}