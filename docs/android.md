# Android 使用文档

## 一键去常规反调试

```typescript
FCAnd.Anti.anti_debug();
```

## 打印堆栈
```typescript
FCAnd.AndOpts.showStacks();
```

## 通用的 Dump dex 方法
```typescript
FCAnd.AndOpts.dump_dex_common();
```
## 过 ssl pinning

将证书 `cert-der.crt` 传到手机，然后调用下面的语句

```typescript
FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");
```

## Hook JNI
方便的 JNI Hook
```typescript
FCAnd.Jni.hookJNI('NewStringUTF', {
    onEnter: function (args) {
        var str = args[1].readCString();
        DMLog.i('NewStringUTF', 'str: ' + str);
        if (null != str) {
            if (str == 'mesh' || str.startsWith('6962')) {
                var lr =  FCAnd.AndOpts.getLR(this.context);
                DMLog.i('NewStringUTF', '(' + Process.arch + ')lr: ' + lr
                    + ', foundso:' + FCAnd.AndOpts.getModuleByAddr(lr) );
                // AndOpts.getStacksModInfo(this.context, 100);
            }
        }
    }
});
```

## 打印 registNatives

```typescript
FCAnd.jni.hook_registNatives();
```

该功能拆分出了一个独立模块，使用频率高的朋友可以使用独立模块
地址：https://github.com/deathmemory/fridaRegstNtv

## 其它

1. 根据地址获取所在 module 的信息
2. 获取模块地址
3. 获取 LR 寄存器值
4. 现成的 Hook url/json/map ...

