# FridaContainer

FridaContainer 整合了网上流行的和自己编写的常用的 frida 脚本，为逆向工作提效之用。

npm build 后，用 Pycharm 打开编辑，可以看到 frida api 代码补全提示。


## 1. 编译和使用

### 1.1 源码直接使用

需要根据自己的需求修改 index.ts，编写实际操作内容。
使用 index.ts 入口方式可以按照以下方式编译和调用。

```sh
$ git clone https://github.com/deathmemory/FridaContainer.git
$ cd FridaContainer/
$ npm install
## after edit index.ts
$ npm run build
$ frida -U -f com.example.android --no-pause -l _fcagent.js
```

- 开发实时编译

```sh
$ npm run watch
```

### 1.2 作为 npm node 模块使用

支持作为 npm node 模拟直接嵌入 typescript 项目中。

[详细引入方式请看这里](docs/use_as_npm_node.md)


## 2. 功能简介

本仓库会持续补充更新。

### 2.1 Android 

- [Android 详细文档](docs/android.md)

1. 一键去常规反调试
2. 打印堆栈
3. 通用的 Dump dex 方法
4. 过 ssl pinning
5. Hook JNI
6. Java methods trace
7. JNI trace

......

### 2.2 iOS

- [iOS 详细文档](docs/ios.md)

1. 便捷的获取函数地址
2. 打印堆栈

### 2.3 FCCommon 跨平台通用方法

| 方法 | 说明 |
| ----- | ---------------------------- |
| showStacksModInfo| 打印指定层数的 sp，并输出 module 信息 (如果有）|
| getModuleByAddr | 根据地址获取模块信息 |
| getLR | 获取 LR 寄存器值 |
| dump_module | dump 指定模块并存储到指定目录 |

## 3. 感谢
[todo 引用参考]

由于引用较多，且时间比较久了，也很难都列出来，以后慢慢列举吧。
感谢无私的代码分享者们。

- [universal-android-ssl-pinning-bypass-with-frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [rida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/)
- [art methods tracer](https://github.com/hluwa/ZenTracer)
- [JNI-Frida-Hook](https://github.com/Areizen/JNI-Frida-Hook)
- [jnitrace](https://github.com/chame1eon/jnitrace)
