# iOS 文档

## 获取函数地址

```typescript
const addr = FCiOS.getFuncAddr('*[NVEnvironment deviceId]');
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
