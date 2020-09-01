//代码在android os: 7.1.2上测试通过
//32位的libart.so 
var opencommon = Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenCommonEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE");
console.log("opencommon addr: "+opencommon);
Interceptor.attach(opencommon, {
    onEnter: function (args) {
      
        //dex起始位置
        var begin = args[1]
        console.log(begin);
        //打印magic
        console.log("magic : " + Memory.readUtf8String(begin))
        //dex fileSize 地址
        var address = parseInt(begin,16) + 0x20
        //dex 大小
        var dex_size = Memory.readInt(ptr(address))

        console.log("dex_size :" + dex_size)
        //dump dex 到/data/data/pkg/目录下
        var file = new File("/sdcard/unpack/" + dex_size + ".dex", "wb")
        file.write(Memory.readByteArray(begin, dex_size))
        file.flush()
        file.close()
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            
        }
    }
});

/*
//64位的libart.so 
var openmemory = Module.findExportByName("libart.so","_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
console.log("openmemory addr: "+openmemory);
Interceptor.attach(openmemory, {
    onEnter: function (args) {
      
        //dex起始位置
        //64位这里获取的args[1]有bug,这里直接读取r0寄存器
        var begin = this.context.x0
        //console.log(this.context.x0);
        //打印magic
        console.log("magic : " + Memory.readUtf8String(begin))
        //dex fileSize 地址
        var address = parseInt(begin,16) + 0x20
        //dex 大小
        var dex_size = Memory.readInt(ptr(address))

        console.log("dex_size :" + dex_size)
        //dump dex 到/data/data/pkg/目录下
        var file = new File("/sdcard/unpack/" + dex_size + ".dex", "wb")
        file.write(Memory.readByteArray(begin, dex_size))
        file.flush()
        file.close()
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            
        }
    }
});
*/

