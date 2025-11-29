/**
 * Frida Scripts - Runtime Instrumentation
 *
 * Scripts para bypass de proteções e monitoramento em runtime:
 * - Root/Jailbreak detection bypass
 * - SSL pinning bypass
 * - Crypto monitoring
 * - Storage monitoring
 * - Network monitoring
 */

// ============================================================================
// ROOT DETECTION BYPASS (Android)
// ============================================================================

var bypassRootDetection = function() {
    console.log("[*] Starting Root Detection Bypass...");

    // Bypass common root detection methods
    var RootPackages = [
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine"
    ];

    var RootBinaries = [
        "su",
        "busybox",
        "supersu",
        "Superuser.apk",
        "KingoUser.apk",
        "SuperSu.apk"
    ];

    var RootProperties = {
        "ro.build.selinux": "0",
        "ro.debuggable": "1",
        "service.adb.root": "1",
        "ro.secure": "0"
    };

    // Hook Runtime.exec
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        var cmdStr = cmd.join(" ");

        // Block root detection commands
        if (cmdStr.indexOf("su") >= 0 ||
            cmdStr.indexOf("which su") >= 0 ||
            cmdStr.indexOf("busybox") >= 0) {
            console.log("[!] Blocked root detection command: " + cmdStr);
            throw new Error("Command not found");
        }

        return this.exec(cmd);
    };

    // Hook File.exists for common root files
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();

        for (var i = 0; i < RootBinaries.length; i++) {
            if (path.indexOf(RootBinaries[i]) >= 0) {
                console.log("[!] Hiding root file: " + path);
                return false;
            }
        }

        return this.exists();
    };

    // Hook PackageManager for root apps
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkgName, flags) {
        if (RootPackages.indexOf(pkgName) >= 0) {
            console.log("[!] Hiding root package: " + pkgName);
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
        }

        return this.getPackageInfo(pkgName, flags);
    };

    // Hook System.getProperty
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        if (key in RootProperties) {
            console.log("[!] Spoofing system property: " + key);
            return RootProperties[key];
        }

        return this.getProperty(key);
    };

    console.log("[+] Root Detection Bypass enabled");
};

// ============================================================================
// JAILBREAK DETECTION BYPASS (iOS)
// ============================================================================

var bypassJailbreakDetection = function() {
    console.log("[*] Starting Jailbreak Detection Bypass...");

    var JailbreakFiles = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/"
    ];

    // Hook fopen
    var fopen = new NativeFunction(
        Module.findExportByName(null, 'fopen'),
        'pointer',
        ['pointer', 'pointer']
    );

    Interceptor.replace(fopen, new NativeCallback(function(path, mode) {
        var pathStr = Memory.readUtf8String(path);

        for (var i = 0; i < JailbreakFiles.length; i++) {
            if (pathStr.indexOf(JailbreakFiles[i]) >= 0) {
                console.log("[!] Blocked jailbreak file access: " + pathStr);
                return NULL;
            }
        }

        return fopen(path, mode);
    }, 'pointer', ['pointer', 'pointer']));

    // Hook stat
    var stat = new NativeFunction(
        Module.findExportByName(null, 'stat'),
        'int',
        ['pointer', 'pointer']
    );

    Interceptor.replace(stat, new NativeCallback(function(path, buf) {
        var pathStr = Memory.readUtf8String(path);

        for (var i = 0; i < JailbreakFiles.length; i++) {
            if (pathStr.indexOf(JailbreakFiles[i]) >= 0) {
                console.log("[!] Blocked jailbreak stat check: " + pathStr);
                return -1;
            }
        }

        return stat(path, buf);
    }, 'int', ['pointer', 'pointer']));

    console.log("[+] Jailbreak Detection Bypass enabled");
};

// ============================================================================
// SSL PINNING BYPASS
// ============================================================================

var bypassSSLPinning = function() {
    console.log("[*] Starting SSL Pinning Bypass...");

    // Android SSL Pinning Bypass
    if (Java.available) {
        // OkHttp3
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log("[!] Bypassing OkHttp3 SSL pinning for: " + hostname);
                return;
            };
            console.log("[+] OkHttp3 SSL Pinning bypassed");
        } catch (e) {
            console.log("[-] OkHttp3 not found");
        }

        // TrustManager
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            var TrustManager = Java.registerClass({
                name: "com.mobscan.CustomTrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {
                        console.log("[!] Client certificates accepted");
                    },
                    checkServerTrusted: function(chain, authType) {
                        console.log("[!] Server certificates accepted");
                    },
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log("[!] Overriding TrustManager");
                return SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };

            console.log("[+] TrustManager SSL Pinning bypassed");
        } catch (e) {
            console.log("[-] TrustManager bypass failed: " + e);
        }

        // WebView SSL Error Handler
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                console.log("[!] WebView SSL error ignored");
                handler.proceed();
            };
            console.log("[+] WebView SSL errors bypassed");
        } catch (e) {
            console.log("[-] WebView not found");
        }
    }

    console.log("[+] SSL Pinning Bypass enabled");
};

// ============================================================================
// CRYPTO MONITORING
// ============================================================================

var monitorCrypto = function() {
    console.log("[*] Starting Crypto Monitoring...");

    if (Java.available) {
        // Monitor Cipher operations
        var Cipher = Java.use("javax.crypto.Cipher");

        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("[CRYPTO] Cipher.getInstance: " + transformation);

            // Warn about weak algorithms
            if (transformation.indexOf("DES") >= 0 && transformation.indexOf("DESede") < 0) {
                console.log("[WARNING] Weak algorithm detected: DES");
            }
            if (transformation.indexOf("ECB") >= 0) {
                console.log("[WARNING] Insecure mode detected: ECB");
            }

            return this.getInstance(transformation);
        };

        // Monitor MessageDigest (hashing)
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[CRYPTO] MessageDigest.getInstance: " + algorithm);

            if (algorithm === "MD5" || algorithm === "SHA-1") {
                console.log("[WARNING] Weak hash algorithm: " + algorithm);
            }

            return this.getInstance(algorithm);
        };

        // Monitor SecureRandom
        var SecureRandom = Java.use("java.security.SecureRandom");
        SecureRandom.$init.overload().implementation = function() {
            console.log("[CRYPTO] SecureRandom initialized");
            return this.$init();
        };

        console.log("[+] Crypto Monitoring enabled");
    }
};

// ============================================================================
// STORAGE MONITORING
// ============================================================================

var monitorStorage = function() {
    console.log("[*] Starting Storage Monitoring...");

    if (Java.available) {
        // Monitor SharedPreferences
        var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferences.putString.implementation = function(key, value) {
            console.log("[STORAGE] SharedPreferences.putString - Key: " + key + ", Value: " + value);
            return this.putString(key, value);
        };

        SharedPreferences.getString.implementation = function(key, defValue) {
            var value = this.getString(key, defValue);
            console.log("[STORAGE] SharedPreferences.getString - Key: " + key + ", Value: " + value);
            return value;
        };

        // Monitor File operations
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function(file, append) {
            var path = file.getAbsolutePath();
            console.log("[STORAGE] FileOutputStream created for: " + path);
            return this.$init(file, append);
        };

        // Monitor SQLite
        try {
            var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

            SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
                console.log("[STORAGE] SQL Query: " + sql);
                return this.execSQL(sql);
            };

            SQLiteDatabase.insert.implementation = function(table, nullColumnHack, values) {
                console.log("[STORAGE] SQLite INSERT into table: " + table);
                console.log("[STORAGE] Values: " + values.toString());
                return this.insert(table, nullColumnHack, values);
            };
        } catch (e) {
            console.log("[-] SQLite monitoring not available");
        }

        console.log("[+] Storage Monitoring enabled");
    }
};

// ============================================================================
// NETWORK MONITORING
// ============================================================================

var monitorNetwork = function() {
    console.log("[*] Starting Network Monitoring...");

    if (Java.available) {
        // Monitor URL connections
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            console.log("[NETWORK] URL.openConnection: " + url);

            if (url.indexOf("http://") === 0) {
                console.log("[WARNING] Unencrypted HTTP connection: " + url);
            }

            return this.openConnection();
        };

        // Monitor OkHttp
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");

            OkHttpClient.newCall.implementation = function(request) {
                var url = request.url().toString();
                var method = request.method();
                console.log("[NETWORK] OkHttp " + method + ": " + url);

                var headers = request.headers();
                var headerNames = headers.names();
                var iterator = headerNames.iterator();
                while (iterator.hasNext()) {
                    var name = iterator.next();
                    var value = headers.get(name);
                    console.log("[NETWORK] Header - " + name + ": " + value);
                }

                return this.newCall(request);
            };

            console.log("[+] OkHttp monitoring enabled");
        } catch (e) {
            console.log("[-] OkHttp not found");
        }

        console.log("[+] Network Monitoring enabled");
    }
};

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

Java.perform(function() {
    console.log("");
    console.log("=================================================");
    console.log("    MOBSCAN Frida Instrumentation v1.1.0");
    console.log("=================================================");
    console.log("");

    // Execute all bypasses and monitors
    bypassRootDetection();
    bypassSSLPinning();
    monitorCrypto();
    monitorStorage();
    monitorNetwork();

    console.log("");
    console.log("[+] All Frida scripts loaded successfully!");
    console.log("=================================================");
    console.log("");
});
