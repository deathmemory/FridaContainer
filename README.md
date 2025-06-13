# FridaContainer

FridaContainer 整合了网上流行的和自己编写的常用的 frida 脚本，为逆向工作提效之用。

npm build 后，用 Pycharm 打开编辑，可以看到 frida api 代码补全提示。

# 注

frida 17.0.0 以上版本 API 变动较大，将新开分支以支持新版本。

## 1. 编译和使用

### 1.1 源码直接使用【推荐】

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

- Setup for android

为 Andriod 手机初始化环境以应用第三方库(gson)

```shell script
$ python setupAndroid.py
```

### 1.2 作为 npm node 模块使用
作为 npm ndoe 使用在新版本中会有问题，具体原因目前还没有时间看，建议用上面的源码推荐方式使用。

~~支持作为 npm node 模拟直接嵌入 typescript 项目中。~~

~~[详细引入方式请看这里](docs/use_as_npm_node.md)~~

### 1.3 赘述几句我当前的使用习惯

1. 使用 `pycharm` 做开发（其他 IDE 也一样）
2. clone 仓库后，在项目根目录创建 agent 目录（已加入 gitignore）在这里开发业务脚本
3. 修改 `index.ts` 引入 agent 目录下的类
4. 单开一个 shell 跑 `npm run watch` 实时编译脚本
5. 不断修改 index 或 agent 的脚本，注入、测试，达到目的。

## 2. 功能简介

本仓库会持续补充更新。

### 2.1 Android 

- [Android 详细文档](docs/android.md)

1. 一键去常规反调试
2. 打印堆栈
3. 通用的 Dump dex 方法
4. 过 ssl pinning （新增 cronet bypass）
5. Hook JNI
6. Java methods trace
7. JNI trace
8. frida multi dex hook(java use)
9. ......

### 2.2 iOS

- [iOS 详细文档](docs/ios.md)

1. 便捷的获取函数地址
2. 模糊查找函数地址
3. 打印堆栈
4. dump ui 结构
5. 常见数据类型转换及打印
6. ......

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

<details>
<summary>感谢参考与引用</summary>

- [universal-android-ssl-pinning-bypass-with-frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [rida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/)
- [art methods tracer](https://github.com/hluwa/ZenTracer)
- [JNI-Frida-Hook](https://github.com/Areizen/JNI-Frida-Hook)
- [jnitrace](https://github.com/chame1eon/jnitrace)
- [frida_hook_libart](https://github.com/lasting-yang/frida_hook_libart)
- [使用Frida简单实现函数粒度脱壳](https://bbs.kanxue.com/thread-260540.htm)
</details>
