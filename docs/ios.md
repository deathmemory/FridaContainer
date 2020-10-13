# iOS 文档

## 获取函数地址

```typescript
const addr = FCiOS.iosOpts.getFuncAddr('*[NVEnvironment deviceId]');
```

## 打印堆栈

```typescript
FCiOS.iosOpts.showStacks(this);
```

## dump ui
```typescript
console.log(FCiOS.iosOpts.dump_ui());
```

## trace openURL
```typescript
FCiOS.iosOpts.trace_url();
```

## trace NSLog
```typescript
FCiOS.iosOpts.trace_NSLog();
```
