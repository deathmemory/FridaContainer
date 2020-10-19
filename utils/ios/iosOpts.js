"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
///<reference path="../../node_modules/@types/frida-gum/index.d.ts"/>
const dmlog_1 = require("../dmlog");
class IosOpts {
    // generic getFuncAddr
    static getFuncAddr(pattern) {
        var tag = 'getFuncAddr';
        var type = (pattern.indexOf(" ") === -1) ? "module" : "objc";
        dmlog_1.DMLog.i(tag, 'getFuncAddr type: ' + type);
        var res = new ApiResolver(type);
        dmlog_1.DMLog.i(tag, 'getFuncAddr ApiResolver: ' + JSON.stringify(res));
        var matches = res.enumerateMatches(pattern);
        dmlog_1.DMLog.i(tag, 'getFuncAddr matches: ' + JSON.stringify(matches));
        var targets = IosOpts.uniqBy(matches, JSON.stringify);
        var targetAddr = NULL;
        targets.forEach(function (target) {
            dmlog_1.DMLog.i(tag, 'target.name: ' + target.name + ', target.address: ' + target.address);
            targetAddr = target.address;
            // end forEach
            return false;
        });
        return targetAddr;
    }
    // remove duplicates from array
    static uniqBy(array, key) {
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }
    static showStacks(thiz) {
        dmlog_1.DMLog.i('showStacks', '\tBacktrace:\n\t' + Thread.backtrace(thiz.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
    }
    static dump_ui() {
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
    static trace_url() {
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
                dmlog_1.DMLog.i('openURL', "Launching URL: " + myJSURL);
                //send(myJSURL);
            }
        });
    }
    static trace_NSLog() {
        const NSLog_ptr = Module.findExportByName("Foundation", "NSLog");
        if (NSLog_ptr) {
            Interceptor.attach(NSLog_ptr, {
                onEnter: function (args) {
                    dmlog_1.DMLog.i('NSLog', new ObjC.Object(args[0]).toString());
                }
            });
        }
        const NSLogv_ptr = Module.findExportByName("Foundation", "NSLogv");
        if (NSLogv_ptr) {
            Interceptor.attach(NSLogv_ptr, {
                onEnter: function (args) {
                    dmlog_1.DMLog.i('NSLogv', new ObjC.Object(args[0]).toString());
                }
            });
        }
    }
}
exports.IosOpts = IosOpts;
