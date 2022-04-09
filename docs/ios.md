# iOS 文档

## 获取函数地址

```typescript
const addr = FCiOS.getFuncAddr('*[NVEnvironment deviceId]');
```

## 模糊查找函数地址

```typescript
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
```

## 打印堆栈

```typescript
FCiOS.showStacks(this);
```

## dump ui
```typescript
console.log(FCiOS.dump_ui());
```

## trace openURL
```typescript
FCiOS.trace_url();
```

## trace NSLog
```typescript
FCiOS.trace_NSLog();
```
