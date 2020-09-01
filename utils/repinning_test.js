/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: repinning_test.js
 * @time: 2020/4/11 9:55 PM
 * @desc:
 */

setTimeout(function () {
    Java.perform(function () {
        var cf = null;
        console.log("");
	    console.log("[.] Cert Pinning Bypass/Re-Pinning");

	    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
	    var FileInputStream = Java.use("java.io.FileInputStream");
	    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
	    var X509Certificate = Java.use("java.security.cert.X509Certificate");
	    var KeyStore = Java.use("java.security.KeyStore");
	    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    var SSLContext = Java.use("javax.net.ssl.SSLContext");

	    // Load CAs from an InputStream
	    console.log("[+] Loading our CA...")
	    cf = CertificateFactory.getInstance("X.509");

	    try {
	    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
	    	console.log("[i] fileInputStream: " + fileInputStream);
	    }
	    catch(err) {
	    	console.log("[o] " + err);
	    }
	    console.log("[i] BufferedInputStream: " + BufferedInputStream);

	    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	    console.log("[i] ===========");
	  	var ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();

		var certInfo = Java.cast(ca, X509Certificate);
	    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    console.log("[+] Creating a KeyStore for our CA...");
	    var keyStoreType = KeyStore.getDefaultType();
	    var keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);

	    // Create a TrustManager that trusts the CAs in our KeyStore
	    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
	    console.log("[+] Our TrustManager is ready...");

	    console.log("[+] Hijacking SSLContext methods now...")
	    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

	   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
	   		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
	   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   		console.log("[+] SSLContext initialized with our custom TrustManager!");
	   	}

        // var SSLContext = Java.use("javax.net.ssl.SSLContext");
        //
        // // SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
        // //     .implementation = function (keyManager, trustManager, sRandom) {
        // //     console.log("[-] Waiting for the app to invoke SSLContext.init()...");
        // //     this.init(keyManager, trustManager, sRandom);
        // //     console.log("[+] SSLContext initialized with our custom TrustManager!");
        // // };
        // SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
	   	// 	console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
	   	// 	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   	// 	console.log("[+] SSLContext initialized with our custom TrustManager!");
	   	// };

        function showStacks() {
            console.log('showStacks', Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));  // 打印堆栈
        }

	   	function hook_InMemoryDexClassLoader() {
            //  dalvik.system.InMemoryDexClassLoader
            const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
            InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                .implementation = function (buff, loader) {
                console.log('FaceBook.TAG' + ' hook_InMemoryDexClassLoader', 'entry');
                this.$init(buff, loader);
                // showStacks();
                var oldcl = Java.classFactory.loader;
                Java.classFactory.loader = this;
                var cls = Java.use('com.facebook.ads.redexgen.X.7J');
                // var cls = this.loadClass('com.facebook.ads.redexgen.X.7J');
                // var reflectClass = Java.use("java.lang.Class");
                // var refcls = Java.cast(cls, reflectClass);
                // console.log('FaceBook.TAG' + ' hook_InMemoryDexClassLoader', 'name: ' + refcls.getName());
                console.log('FaceBook.TAG' + ' hook_InMemoryDexClassLoader', 'cls: ' + cls);
                cls.A03.implementation = function (conn, set1, set2) {
                    console.log('A03', 'entry');
                    console.log('A03', 'conn: ' + conn);
                    console.log('A03', 'set1: ' + set1);
                    console.log('A03', 'set2: ' + set2);
                    // this.A03(conn, set1, set2);
                    console.log('A03', 'Just returned');
                };
                Java.classFactory.loader = oldcl;
                // const _7J = loader0.loadClass('com.facebook.ads.redexgen.X.7J');
                // console.log('FaceBook.TAG' + ' hook_InMemoryDexClassLoader', 'loader0: ' + loader0);
                // console.log('FaceBook.TAG' + ' hook_InMemoryDexClassLoader', 'find cls');

                return undefined;
            }
        }
        
        function hook_DexClassLoader() {
            // dalvik.system.DexClassLoader;
            const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
            DexClassLoader.$init.implementation = function (p1, p2, p3, p4) {
                console.log('FaceBook.TAG' + ' hook_DexClassLoader', 'entry');
                return this.$init(p1, p2, p3, p4);
            }
        }

        function hook_https() {
            const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.getServerCertificates.implementation = function () {
                console.log('getServerCertificates', 'entry');
                return this.getServerCertificates();
            }
        }

        function hook_HttpURLConnection() {
            const HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.setConnectTimeout.implementation = function (num) {
                console.log('hook_HttpURLConnection', 'setConnectTimeout: ' + num);
                this.setConnectTimeout(num);
            }
        }

        hook_InMemoryDexClassLoader();
        hook_DexClassLoader();
        // hook_HttpURLConnection();
        // hook_https();
    });
}, 0);

