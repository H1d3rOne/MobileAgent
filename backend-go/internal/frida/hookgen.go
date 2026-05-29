package frida

import (
	"fmt"
	"strings"

	"github.com/mobileagent/backend-go/internal/analyzer"
)

type GeneratedHook struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Code        string `json:"code"`
	Reason      string `json:"reason"`
}

func GenerateHooksFromAnalysis(antiDetect *analyzer.AntiDetectResult, crypto []analyzer.CryptoFinding, strings_ *analyzer.StringsResult) []GeneratedHook {
	var hooks []GeneratedHook

	if antiDetect != nil {
		hooks = append(hooks, generateAntiDetectHooks(antiDetect)...)
	}
	if len(crypto) > 0 {
		hooks = append(hooks, generateCryptoHooks(crypto)...)
	}
	if strings_ != nil && strings_.Firebase != nil {
		hooks = append(hooks, generateFirebaseHook(strings_.Firebase))
	}

	return hooks
}

func generateAntiDetectHooks(ad *analyzer.AntiDetectResult) []GeneratedHook {
	var hooks []GeneratedHook

	if ad.Summary.HasRootDetection {
		classes := extractClassNames(ad.RootDetection)
		hook := GeneratedHook{
			ID:          "gen-root-bypass",
			Name:        "Root Detection Bypass (Targeted)",
			Category:    "bypass",
			Description: "Bypass root detection based on detected patterns",
			Reason:      fmt.Sprintf("Found %d root detection patterns", len(ad.RootDetection)),
			Code:        buildRootBypassHook(classes),
		}
		hooks = append(hooks, hook)
	}

	if ad.Summary.HasFridaDetection {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-frida-bypass",
			Name:        "Anti-Frida Bypass (Targeted)",
			Category:    "bypass",
			Description: "Bypass frida detection based on detected patterns",
			Reason:      fmt.Sprintf("Found %d frida detection patterns", len(ad.FridaDetection)),
			Code:        buildFridaBypassHook(ad.FridaDetection),
		})
	}

	if ad.Summary.HasEmulatorDetection {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-emulator-bypass",
			Name:        "Emulator Detection Bypass (Targeted)",
			Category:    "bypass",
			Description: "Bypass emulator detection based on detected patterns",
			Reason:      fmt.Sprintf("Found %d emulator detection patterns", len(ad.EmulatorDetection)),
			Code:        buildEmulatorBypassHook(ad.EmulatorDetection),
		})
	}

	if ad.Summary.HasDebugDetection {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-debug-bypass",
			Name:        "Anti-Debug Bypass (Targeted)",
			Category:    "bypass",
			Description: "Bypass debug detection based on detected patterns",
			Reason:      fmt.Sprintf("Found %d debug detection patterns", len(ad.DebugDetection)),
			Code:        buildDebugBypassHook(),
		})
	}

	return hooks
}

func generateCryptoHooks(findings []analyzer.CryptoFinding) []GeneratedHook {
	algos := map[string]bool{}
	for _, f := range findings {
		algos[strings.ToLower(f.Algorithm)] = true
	}

	hook := GeneratedHook{
		ID:          "gen-crypto-monitor",
		Name:        "Crypto Operations Monitor (Targeted)",
		Category:    "monitoring",
		Description: "Monitor cryptographic operations detected in the app",
		Reason:      fmt.Sprintf("Found %d crypto usages across %d algorithms", len(findings), len(algos)),
		Code:        buildCryptoMonitorHook(algos),
	}
	return []GeneratedHook{hook}
}

func generateFirebaseHook(fc *analyzer.FirebaseConfig) GeneratedHook {
	return GeneratedHook{
		ID:          "gen-firebase-monitor",
		Name:        "Firebase Traffic Monitor",
		Category:    "monitoring",
		Description: "Monitor Firebase API calls and data",
		Reason:      fmt.Sprintf("Firebase config detected: project=%s", fc.ProjectID),
		Code:        buildFirebaseMonitorHook(fc),
	}
}

func extractClassNames(findings []analyzer.DetectionFinding) []string {
	classes := map[string]bool{}
	for _, f := range findings {
		parts := strings.Split(f.File, "/")
		if len(parts) > 1 && strings.HasSuffix(f.File, ".smali") {
			className := strings.TrimSuffix(f.File, ".smali")
			className = strings.TrimPrefix(className, "smali/")
			className = strings.ReplaceAll(className, "/", ".")
			classes[className] = true
		}
	}
	out := make([]string, 0, len(classes))
	for c := range classes {
		out = append(out, c)
	}
	return out
}

func buildRootBypassHook(classes []string) string {
	var sb strings.Builder
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Root Detection Bypass - Targeted");

    // Hook Runtime.exec to block su checks
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmd) {
        var cmdStr = cmd.join(" ");
        if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("which") !== -1) {
            console.log("[!] Blocked exec: " + cmdStr);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    // Hook File.exists for su binary checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/app/Superuser.apk",
                       "/system/xbin/busybox", "/data/local/bin/su", "/data/local/xbin/su"];
        for (var i = 0; i < blocked.length; i++) {
            if (path === blocked[i]) {
                console.log("[!] Blocked File.exists: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // Hook PackageManager for root app checks
    var PM = Java.use("android.app.ApplicationPackageManager");
    PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
        var rootPkgs = ["com.noshufou.android.su", "com.thirdparty.superuser",
                        "eu.chainfire.supersu", "com.koushikdutta.superuser",
                        "com.topjohnwu.magisk"];
        for (var i = 0; i < rootPkgs.length; i++) {
            if (pkg === rootPkgs[i]) {
                console.log("[!] Blocked getPackageInfo: " + pkg);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
        }
        return this.getPackageInfo(pkg, flags);
    };

    // Hook Build.TAGS
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
`)

	if len(classes) > 0 {
		sb.WriteString("\n    // Target specific detected classes\n")
		for _, cls := range classes {
			if len(cls) > 0 {
				sb.WriteString(fmt.Sprintf(`    try {
        var target = Java.use("%s");
        var methods = target.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var methodName = methods[i].getName();
            if (methodName.toLowerCase().indexOf("root") !== -1 ||
                methodName.toLowerCase().indexOf("detect") !== -1 ||
                methodName.toLowerCase().indexOf("check") !== -1) {
                console.log("[*] Hooking: %s." + methodName);
            }
        }
    } catch(e) {}
`, cls, cls))
			}
		}
	}

	sb.WriteString("});\n")
	return sb.String()
}

func buildFridaBypassHook(findings []analyzer.DetectionFinding) string {
	return `Java.perform(function() {
    console.log("[*] Anti-Frida Bypass - Targeted");

    // Hide frida from /proc/self/maps
    var fopen = Module.findExportByName("libc.so", "fopen");
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf("/proc") !== -1 && this.path.indexOf("maps") !== -1) {
                console.log("[!] Intercepted maps read");
            }
        }
    });

    // Block port scanning for frida
    var connect = Module.findExportByName("libc.so", "connect");
    Interceptor.attach(connect, {
        onEnter: function(args) {
            var sockAddr = args[1];
            var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
            if (port === 27042 || port === 27043) {
                console.log("[!] Blocked connect to frida port: " + port);
                args[1] = ptr(0);
            }
        }
    });

    // Hook strstr to hide frida strings
    var strstr = Module.findExportByName("libc.so", "strstr");
    Interceptor.attach(strstr, {
        onEnter: function(args) {
            this.haystack = args[0];
            this.needle = args[1].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.needle && (this.needle.indexOf("frida") !== -1 ||
                this.needle.indexOf("xposed") !== -1 ||
                this.needle.indexOf("substrate") !== -1)) {
                retval.replace(ptr(0));
            }
        }
    });

    // Hook dlopen to hide frida libraries
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                var lib = args[0].readUtf8String();
                if (lib && lib.indexOf("frida") !== -1) {
                    console.log("[!] Blocked dlopen: " + lib);
                    args[0] = Memory.allocUtf8String("/dev/null");
                }
            }
        });
    }

    console.log("[+] Anti-Frida bypass active");
});
`
}

func buildEmulatorBypassHook(findings []analyzer.DetectionFinding) string {
	return `Java.perform(function() {
    console.log("[*] Emulator Detection Bypass - Targeted");

    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "walleye";
    Build.PRODUCT.value = "walleye";
    Build.HARDWARE.value = "walleye";
    Build.BOARD.value = "walleye";
    Build.HOST.value = "wphr1.hot.corp.google.com";
    Build.TAGS.value = "release-keys";

    // Hook TelephonyManager
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getDeviceId.overload().implementation = function() {
        return "352521080439546";
    };
    TelephonyManager.getSubscriberId.overload().implementation = function() {
        return "310260000000000";
    };
    TelephonyManager.getSimSerialNumber.overload().implementation = function() {
        return "89014103211118510720";
    };
    TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
        return "T-Mobile";
    };

    // Hook File.exists for emulator-specific files
    var File = Java.use("java.io.File");
    var origExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var emuFiles = ["/dev/socket/qemud", "/dev/qemu_pipe",
                        "/system/lib/libc_malloc_debug_qemu.so",
                        "/sys/qemu_trace", "/system/bin/qemu-props"];
        for (var i = 0; i < emuFiles.length; i++) {
            if (path === emuFiles[i]) {
                console.log("[!] Blocked emu file check: " + path);
                return false;
            }
        }
        return origExists.call(this);
    };

    // Hook SystemProperties for emulator detection
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function(key) {
        if (key === "ro.hardware" || key === "ro.product.device") {
            return "walleye";
        }
        if (key === "ro.kernel.qemu" || key === "ro.boot.qemu") {
            return "0";
        }
        if (key === "init.svc.qemud" || key === "init.svc.qemu-props") {
            return "";
        }
        return this.get(key);
    };

    console.log("[+] Emulator bypass active");
});
`
}

func buildDebugBypassHook() string {
	return `Java.perform(function() {
    console.log("[*] Anti-Debug Bypass - Targeted");

    // Hook Debug.isDebuggerConnected
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[!] isDebuggerConnected -> false");
        return false;
    };

    // Hook /proc/self/status TracerPid
    var fopen = Module.findExportByName("libc.so", "fopen");
    var fgets = Module.findExportByName("libc.so", "fgets");
    var tracerPidFile = false;

    Interceptor.attach(fopen, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf("/proc") !== -1 && path.indexOf("status") !== -1) {
                tracerPidFile = true;
            }
        }
    });

    Interceptor.attach(fgets, {
        onLeave: function(retval) {
            if (tracerPidFile && retval && !retval.isNull()) {
                var line = retval.readUtf8String();
                if (line && line.indexOf("TracerPid") !== -1) {
                    retval.writeUtf8String("TracerPid:\t0\n");
                    console.log("[!] TracerPid -> 0");
                }
            }
        }
    });

    // Block ptrace
    var ptrace = Module.findExportByName("libc.so", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                console.log("[!] ptrace blocked");
            },
            onLeave: function(retval) {
                retval.replace(ptr(0));
            }
        });
    }

    console.log("[+] Anti-debug bypass active");
});
`
}

func buildCryptoMonitorHook(algos map[string]bool) string {
	var sb strings.Builder
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Crypto Monitor - Targeted");

    // Monitor Cipher operations
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[CRYPTO] Cipher.getInstance: " + algo);
        return this.getInstance(algo);
    };
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);
        console.log("[CRYPTO] Cipher.doFinal: input=" + input.length + " bytes, output=" + result.length + " bytes, algo=" + this.getAlgorithm());
        return result;
    };

    // Monitor MessageDigest (hashing)
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[CRYPTO] MessageDigest.getInstance: " + algo);
        return this.getInstance(algo);
    };
    MessageDigest.digest.overload("[B").implementation = function(input) {
        var result = this.digest(input);
        var hex = "";
        for (var i = 0; i < Math.min(result.length, 16); i++) {
            hex += ("0" + (result[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[CRYPTO] digest: algo=" + this.getAlgorithm() + " input=" + input.length + "B hash=" + hex + "...");
        return result;
    };

    // Monitor SecretKeySpec creation
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, algo) {
        var hex = "";
        for (var i = 0; i < Math.min(key.length, 8); i++) {
            hex += ("0" + (key[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[CRYPTO] SecretKeySpec: algo=" + algo + " key=" + hex + "... (" + key.length + " bytes)");
        return this.$init(key, algo);
    };

    // Monitor Mac operations
    var Mac = Java.use("javax.crypto.Mac");
    Mac.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[CRYPTO] Mac.getInstance: " + algo);
        return this.getInstance(algo);
    };
`)

	if algos["rsa"] || algos["ecdsa"] || algos["ecdh"] {
		sb.WriteString(`
    // Monitor KeyPairGenerator (asymmetric)
    var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
    KeyPairGenerator.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[CRYPTO] KeyPairGenerator: " + algo);
        return this.getInstance(algo);
    };
`)
	}

	sb.WriteString(`
    console.log("[+] Crypto monitoring active");
});
`)
	return sb.String()
}

func buildFirebaseMonitorHook(fc *analyzer.FirebaseConfig) string {
	projectID := fc.ProjectID
	if projectID == "" {
		projectID = "unknown"
	}
	return fmt.Sprintf(`Java.perform(function() {
    console.log("[*] Firebase Monitor - Project: %s");

    // Monitor Firestore reads/writes
    try {
        var FirebaseFirestore = Java.use("com.google.firebase.firestore.FirebaseFirestore");
        FirebaseFirestore.collection.implementation = function(path) {
            console.log("[FIREBASE] Firestore.collection: " + path);
            return this.collection(path);
        };
    } catch(e) {}

    // Monitor Realtime Database
    try {
        var DatabaseReference = Java.use("com.google.firebase.database.DatabaseReference");
        DatabaseReference.setValue.overload("java.lang.Object").implementation = function(value) {
            console.log("[FIREBASE] DB.setValue: path=" + this.getPath().toString() + " value=" + value);
            return this.setValue(value);
        };
    } catch(e) {}

    // Monitor Firebase Auth
    try {
        var FirebaseAuth = Java.use("com.google.firebase.auth.FirebaseAuth");
        FirebaseAuth.signInWithEmailAndPassword.implementation = function(email, password) {
            console.log("[FIREBASE] signIn: email=" + email);
            return this.signInWithEmailAndPassword(email, password);
        };
    } catch(e) {}

    // Monitor Cloud Functions calls
    try {
        var HttpsCallableReference = Java.use("com.google.firebase.functions.HttpsCallableReference");
        HttpsCallableReference.call.overload("java.lang.Object").implementation = function(data) {
            console.log("[FIREBASE] CloudFunction call: " + JSON.stringify(data));
            return this.call(data);
        };
    } catch(e) {}

    // Monitor Analytics events
    try {
        var FirebaseAnalytics = Java.use("com.google.firebase.analytics.FirebaseAnalytics");
        FirebaseAnalytics.logEvent.implementation = function(name, params) {
            console.log("[FIREBASE] Analytics: " + name);
            return this.logEvent(name, params);
        };
    } catch(e) {}

    console.log("[+] Firebase monitoring active");
});
`, projectID)
}
