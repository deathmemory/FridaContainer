import {DMLog} from "../dmlog";

export class IosOpts {
// generic getFuncAddr
    static getFuncAddr(pattern: string) : NativePointer {
        var tag = 'getFuncAddr';
        var type: ApiResolverType = (pattern.indexOf(" ") === -1) ? "module" : "objc";
        DMLog.i(tag, 'getFuncAddr type: ' + type);
        var res: ApiResolver = new ApiResolver(type);
        DMLog.i(tag, 'getFuncAddr ApiResolver: ' + JSON.stringify(res));
        var matches = res.enumerateMatches(pattern);
        DMLog.i(tag, 'getFuncAddr matches: ' + JSON.stringify(matches));
        var targets = IosOpts.uniqBy(matches, JSON.stringify);

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
    static uniqBy(array: any, key: any) {
        var seen: any = {};
        return array.filter(function (item: any) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }

    static showStacks(thiz: any) {
        DMLog.i('showStacks', '\tBacktrace:\n\t' + Thread.backtrace(thiz.context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
    }
}