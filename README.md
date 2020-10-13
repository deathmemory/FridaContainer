# FridaContainer

FridaContainer 集成了网上流行的和自己编写的常用的 frida 脚本，为逆向工作提效之用。


## 编译和使用

```sh
$ git clone https://github.com/deathmemory/FridaContainer.git
$ cd FridaContainer/
$ npm install
$ frida -U -f com.example.android --no-pause -l _fcagent.js
```

## 开发实时编译

```sh
$ npm run watch
```

## 功能简介

本仓库会持续补充更新。

### Android 

- [Android 详细文档](docs/android.md)

1. 一键去常规反调试
2. 打印堆栈
3. 通用的 Dump dex 方法
4. 过 ssl pinning
5. Hook JNI

......

### iOS

- [iOS 详细文档](docs/ios.md)

1. 便捷的获取函数地址
2. 打印堆栈

### FCCommon 跨平台通用方法


| 方法 | 说明 |
| ----- | ---------------------------- |
| showStacksModInfo| 打印指定层数的 sp，并输出 module 信息 (如果有）|
| getModuleByAddr | 根据地址获取模块信息 |
| getLR | 获取 LR 寄存器值 |


## 感谢
[todo 引用参考]

由于引用较多，且时间比较久了，也很难都列出来，以后慢慢列举吧。
感谢无私的代码分享者们。
