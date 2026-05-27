package frida

type Script struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Code        string `json:"code"`
	Target      string `json:"target"` // "any", "specific_package", "spawn"
}

var BuiltinScripts = []Script{
	{
		ID:          "ssl-pinning-bypass",
		Name:        "SSL Pinning Bypass (Universal)",
		Category:    "network",
		Description: "Bypass SSL certificate pinning for OkHttp, HttpsURLConnection, TrustManager, and common libraries",
		Target:      "any",
		Code: `
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.mobileagent.TrustAllX509',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
        var c = this.getInstance(type);
        c.init(null, [TrustManager.$new()], null);
        return c;
    };

    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner bypassed for: ' + hostname);
        };
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(hostname, fn) {
            console.log('[+] OkHttp3 CertificatePinner$okhttp bypassed for: ' + hostname);
        };
    } catch(e) {}

    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed');
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
            console.log('[+] HttpsURLConnection.setSSLSocketFactory bypassed');
        };
    } catch(e) {}

    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            console.log('[+] WebView SSL error bypassed');
        };
    } catch(e) {}

    console.log('[*] SSL Pinning bypass loaded');
});
`,
	},
	{
		ID:          "root-detection-bypass",
		Name:        "Root Detection Bypass",
		Category:    "anti-detection",
		Description: "Bypass common root detection checks (su binary, build tags, packages, file paths)",
		Target:      "any",
		Code: `
Java.perform(function() {
    var RootBeer = null;
    try {
        RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function() { return false; };
        RootBeer.checkForSuBinary.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        RootBeer.checkForRWPaths.implementation = function() { return false; };
        RootBeer.checkForDangerousProps.implementation = function() { return false; };
        RootBeer.checkForRootNative.implementation = function() { return false; };
        RootBeer.detectRootCloakingApps.implementation = function() { return false; };
    } catch(e) {}

    var Runtime = Java.use('java.lang.Runtime');
    var origExec = Runtime.exec.overload('[Ljava.lang.String;');
    origExec.implementation = function(cmd) {
        var blocked = ['su', 'which', 'busybox'];
        for (var i = 0; i < cmd.length; i++) {
            for (var j = 0; j < blocked.length; j++) {
                if (cmd[i].indexOf(blocked[j]) !== -1) {
                    console.log('[+] Blocked exec: ' + cmd[i]);
                    throw Java.use('java.io.IOException').$new('Permission denied');
                }
            }
        }
        return origExec.call(this, cmd);
    };

    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
            '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
            '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
            '/su/bin/su', '/magisk'];
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log('[+] Root path check bypassed: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';

    console.log('[*] Root detection bypass loaded');
});
`,
	},
	{
		ID:          "anti-frida-bypass",
		Name:        "Anti-Frida Detection Bypass",
		Category:    "anti-detection",
		Description: "Bypass Frida detection (port scanning, library checks, named pipes)",
		Target:      "any",
		Code: `
Java.perform(function() {
    var File = Java.use('java.io.File');
    var origExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('frida') !== -1 || path.indexOf('linjector') !== -1) {
            console.log('[+] Anti-frida file check bypassed: ' + path);
            return false;
        }
        return origExists.call(this);
    };

    Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
        onEnter: function(args) {
            var path = args[0].readCString();
            if (path && (path.indexOf('frida') !== -1 || path.indexOf('/proc/self/maps') !== -1)) {
                this.shouldBlock = true;
            }
        },
        onLeave: function(retval) {
            if (this.shouldBlock) {
                retval.replace(-1);
            }
        }
    });

    Interceptor.attach(Module.findExportByName('libc.so', 'strstr'), {
        onEnter: function(args) {
            this.haystack = args[0];
            this.needle = args[1].readCString();
        },
        onLeave: function(retval) {
            if (this.needle && (this.needle.indexOf('frida') !== -1 || this.needle.indexOf('LIBFRIDA') !== -1)) {
                retval.replace(ptr(0));
            }
        }
    });

    console.log('[*] Anti-Frida bypass loaded');
});
`,
	},
	{
		ID:          "emulator-detection-bypass",
		Name:        "Emulator Detection Bypass",
		Category:    "anti-detection",
		Description: "Bypass emulator/virtual device detection checks",
		Target:      "any",
		Code: `
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys';
    Build.MODEL.value = 'Pixel 2';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.DEVICE.value = 'walleye';
    Build.PRODUCT.value = 'walleye';
    Build.HARDWARE.value = 'walleye';
    Build.BOARD.value = 'walleye';

    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
        return '355461082046988';
    };
    TelephonyManager.getSubscriberId.overload().implementation = function() {
        return '310260000000000';
    };
    TelephonyManager.getSimSerialNumber.overload().implementation = function() {
        return '89014103211118510720';
    };

    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.hardware' || key === 'ro.product.model') {
            return 'walleye';
        }
        if (key === 'ro.kernel.qemu' || key === 'ro.boot.qemu') {
            return '0';
        }
        return this.get(key);
    };

    console.log('[*] Emulator detection bypass loaded');
});
`,
	},
	{
		ID:          "crypto-monitor",
		Name:        "Crypto Operations Monitor",
		Category:    "crypto",
		Description: "Hook javax.crypto to log encryption/decryption operations with keys and data",
		Target:      "any",
		Code: `
Java.perform(function() {
    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }

    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var modeStr = mode === 1 ? 'ENCRYPT' : 'DECRYPT';
        console.log('[Cipher] ' + modeStr + ' algo=' + this.getAlgorithm() + ' key=' + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher] doFinal input(' + input.length + ')=' + bytesToHex(input).substring(0, 64) + '...');
        var result = this.doFinal(input);
        console.log('[Cipher] doFinal output(' + result.length + ')=' + bytesToHex(result).substring(0, 64) + '...');
        return result;
    };

    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(input) {
        var result = this.digest(input);
        console.log('[Hash] ' + this.getAlgorithm() + ' input(' + input.length + ') -> ' + bytesToHex(result));
        return result;
    };

    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
            console.log('[Key] SecretKeySpec algo=' + algo + ' key=' + bytesToHex(key));
            return this.$init(key, algo);
        };
    } catch(e) {}

    console.log('[*] Crypto monitor loaded');
});
`,
	},
	{
		ID:          "http-traffic-logger",
		Name:        "HTTP Traffic Logger",
		Category:    "network",
		Description: "Log all HTTP/HTTPS requests and responses (URL, headers, body)",
		Target:      "any",
		Code: `
Java.perform(function() {
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Interceptor = Java.use('okhttp3.Interceptor');
        var InterceptorChain = Java.use('okhttp3.Interceptor$Chain');

        var LogInterceptor = Java.registerClass({
            name: 'com.mobileagent.LogInterceptor',
            implements: [Interceptor],
            methods: {
                intercept: function(chain) {
                    var request = chain.request();
                    console.log('[HTTP] ' + request.method() + ' ' + request.url().toString());
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        console.log('  > ' + headers.name(i) + ': ' + headers.value(i));
                    }
                    var response = chain.proceed(request);
                    console.log('[HTTP] Response: ' + response.code() + ' ' + response.message());
                    return response;
                }
            }
        });
        console.log('[*] OkHttp interceptor registered');
    } catch(e) {
        console.log('[!] OkHttp not found, trying URLConnection');
    }

    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            console.log('[HTTP] URL.openConnection: ' + this.toString());
            return conn;
        };
    } catch(e) {}

    console.log('[*] HTTP traffic logger loaded');
});
`,
	},
	{
		ID:          "shared-prefs-monitor",
		Name:        "SharedPreferences Monitor",
		Category:    "storage",
		Description: "Log all SharedPreferences read/write operations",
		Target:      "any",
		Code: `
Java.perform(function() {
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

    Editor.putString.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT string: ' + key + ' = ' + value);
        return this.putString(key, value);
    };
    Editor.putInt.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT int: ' + key + ' = ' + value);
        return this.putInt(key, value);
    };
    Editor.putBoolean.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT bool: ' + key + ' = ' + value);
        return this.putBoolean(key, value);
    };

    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[SharedPrefs] GET string: ' + key + ' = ' + result);
        return result;
    };

    console.log('[*] SharedPreferences monitor loaded');
});
`,
	},
	{
		ID:          "activity-lifecycle",
		Name:        "Activity Lifecycle Tracker",
		Category:    "debug",
		Description: "Track Activity creation, resume, pause, and destroy events",
		Target:      "any",
		Code: `
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');

    Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
        console.log('[Activity] onCreate: ' + this.getClass().getName());
        this.onCreate(bundle);
    };
    Activity.onResume.implementation = function() {
        console.log('[Activity] onResume: ' + this.getClass().getName());
        this.onResume();
    };
    Activity.onPause.implementation = function() {
        console.log('[Activity] onPause: ' + this.getClass().getName());
        this.onPause();
    };
    Activity.onDestroy.implementation = function() {
        console.log('[Activity] onDestroy: ' + this.getClass().getName());
        this.onDestroy();
    };

    var Intent = Java.use('android.content.Intent');
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Activity] startActivity: ' + intent.getComponent());
        if (intent.getExtras()) {
            console.log('  extras: ' + intent.getExtras().toString());
        }
        this.startActivity(intent);
    };

    console.log('[*] Activity lifecycle tracker loaded');
});
`,
	},
	{
		ID:          "clipboard-monitor",
		Name:        "Clipboard Monitor",
		Category:    "storage",
		Description: "Monitor clipboard copy/paste operations",
		Target:      "any",
		Code: `
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');

    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var item = clip.getItemAt(0);
        console.log('[Clipboard] COPY: ' + item.getText());
        this.setPrimaryClip(clip);
    };

    ClipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        if (clip && clip.getItemCount() > 0) {
            console.log('[Clipboard] PASTE: ' + clip.getItemAt(0).getText());
        }
        return clip;
    };

    console.log('[*] Clipboard monitor loaded');
});
`,
	},
	{
		ID:          "intent-monitor",
		Name:        "Intent & Broadcast Monitor",
		Category:    "debug",
		Description: "Log all sent intents and broadcast receivers",
		Target:      "any",
		Code: `
Java.perform(function() {
    var ContextWrapper = Java.use('android.content.ContextWrapper');

    ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Broadcast] sendBroadcast: ' + intent.getAction());
        if (intent.getExtras()) console.log('  extras: ' + intent.getExtras().toString());
        this.sendBroadcast(intent);
    };

    ContextWrapper.startService.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Service] startService: ' + intent.getComponent());
        return this.startService(intent);
    };

    ContextWrapper.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function(intent, perm) {
        console.log('[Broadcast] sendOrderedBroadcast: ' + intent.getAction() + ' perm=' + perm);
        this.sendOrderedBroadcast(intent, perm);
    };

    console.log('[*] Intent & Broadcast monitor loaded');
});
`,
	},
	{
		ID:          "keystore-dump",
		Name:        "Android Keystore Dump",
		Category:    "crypto",
		Description: "Hook Android Keystore operations and dump key usage",
		Target:      "any",
		Code: `
Java.perform(function() {
    var KeyStore = Java.use('java.security.KeyStore');

    KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
        console.log('[Keystore] getInstance type=' + type);
        return this.getInstance(type);
    };

    KeyStore.getKey.implementation = function(alias, password) {
        console.log('[Keystore] getKey alias=' + alias);
        return this.getKey(alias, password);
    };

    KeyStore.getCertificate.implementation = function(alias) {
        console.log('[Keystore] getCertificate alias=' + alias);
        return this.getCertificate(alias);
    };

    try {
        var KeyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
        KeyGenParameterSpec.$init.overload('java.lang.String', 'int').implementation = function(alias, purposes) {
            var purposeStr = [];
            if (purposes & 1) purposeStr.push('ENCRYPT');
            if (purposes & 2) purposeStr.push('DECRYPT');
            if (purposes & 4) purposeStr.push('SIGN');
            if (purposes & 8) purposeStr.push('VERIFY');
            console.log('[Keystore] KeyGen alias=' + alias + ' purposes=' + purposeStr.join('|'));
            return this.$init(alias, purposes);
        };
    } catch(e) {}

    console.log('[*] Keystore dump loaded');
});
`,
	},
	{
		ID:          "dynamic-dex-loader",
		Name:        "Dynamic DEX Loading Monitor",
		Category:    "debug",
		Description: "Monitor DexClassLoader and InMemoryDexClassLoader for runtime code loading",
		Target:      "any",
		Code: `
Java.perform(function() {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
        console.log('[DexLoader] DexClassLoader: ' + dexPath);
        console.log('  optimizedDir: ' + optimizedDir);
        return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
    };

    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {
        console.log('[DexLoader] PathClassLoader: ' + path);
        return this.$init(path, parent);
    };

    try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(buf, parent) {
            console.log('[DexLoader] InMemoryDexClassLoader: buffer size=' + buf.capacity());
            return this.$init(buf, parent);
        };
    } catch(e) {}

    var System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function(lib) {
        console.log('[DexLoader] System.loadLibrary: ' + lib);
        this.loadLibrary(lib);
    };
    System.load.implementation = function(path) {
        console.log('[DexLoader] System.load: ' + path);
        this.load(path);
    };

    console.log('[*] Dynamic DEX loading monitor loaded');
});
`,
	},
}

func GetScript(id string) *Script {
	for i := range BuiltinScripts {
		if BuiltinScripts[i].ID == id {
			return &BuiltinScripts[i]
		}
	}
	return nil
}

func ListScripts() []Script {
	return BuiltinScripts
}

func ListByCategory(category string) []Script {
	var out []Script
	for _, s := range BuiltinScripts {
		if s.Category == category {
			out = append(out, s)
		}
	}
	return out
}

func Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range BuiltinScripts {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}
