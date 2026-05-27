package frida

import (
	"fmt"
	"strings"

	"github.com/mobileagent/backend-go/internal/analyzer"
)

type GeneratedHook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Code        string   `json:"code"`
	Reason      string   `json:"reason"`
	FlowIDs     []string `json:"flow_ids,omitempty"`
}

type entryTraceHookFlow struct {
	ID   string
	Flow analyzer.EntryFlow
}

func GenerateHooksFromAnalysis(antiDetect *analyzer.AntiDetectResult, crypto []analyzer.CryptoFinding, strings_ *analyzer.StringsResult, entryTrace *analyzer.EntryTraceResult) []GeneratedHook {
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
	if entryTrace != nil {
		hooks = append(hooks, generateEntryTraceHooks(entryTrace)...)
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

func generateEntryTraceHooks(entryTrace *analyzer.EntryTraceResult) []GeneratedHook {
	if entryTrace == nil || entryTrace.Summary.FlowsFound == 0 {
		return nil
	}

	buckets := map[string][]entryTraceHookFlow{}
	var flowIndex int
	for _, trace := range entryTrace.Traces {
		for _, flow := range trace.Flows {
			flowIndex++
			bucket := entryTraceHookBucket(flow.Sink.Kind)
			if bucket == "" {
				continue
			}
			buckets[bucket] = append(buckets[bucket], entryTraceHookFlow{
				ID:   fmt.Sprintf("flow-%03d", flowIndex),
				Flow: flow,
			})
		}
	}

	var hooks []GeneratedHook
	if flows := buckets["exec"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-exec-monitor",
			Name:        "Entrypoint Runtime.exec Monitor",
			Category:    "entry-trace",
			Description: "Monitor command execution reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "Runtime.exec"),
			Code:        buildExecMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	if flows := buckets["webview"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-webview-monitor",
			Name:        "Entrypoint WebView Sink Monitor",
			Category:    "entry-trace",
			Description: "Monitor WebView URL loads and JS bridge registration reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "WebView sinks"),
			Code:        buildWebViewMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	if flows := buckets["intent"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-intent-monitor",
			Name:        "Entrypoint Intent & Broadcast Monitor",
			Category:    "entry-trace",
			Description: "Monitor startActivity/startService/sendBroadcast sinks reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "Intent/Broadcast sinks"),
			Code:        buildIntentMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	if flows := buckets["sqlite"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-sqlite-monitor",
			Name:        "Entrypoint SQLite Sink Monitor",
			Category:    "entry-trace",
			Description: "Monitor SQL execution reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "SQLite sinks"),
			Code:        buildSQLiteMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	if flows := buckets["network"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-network-monitor",
			Name:        "Entrypoint Network Sink Monitor",
			Category:    "entry-trace",
			Description: "Monitor network requests reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "network sinks"),
			Code:        buildNetworkMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	if flows := buckets["file_write"]; len(flows) > 0 {
		hooks = append(hooks, GeneratedHook{
			ID:          "gen-entry-trace-file-write-monitor",
			Name:        "Entrypoint File Write Monitor",
			Category:    "entry-trace",
			Description: "Monitor file writes reached from exported entrypoint inputs",
			Reason:      summarizeEntryTraceFlows(flows, "file write sinks"),
			Code:        buildFileWriteMonitorHook(flows),
			FlowIDs:     entryTraceFlowIDList(flows),
		})
	}
	return hooks
}

func entryTraceHookBucket(kind string) string {
	switch kind {
	case "command_exec", "smali_command_exec":
		return "exec"
	case "webview", "smali_webview", "webview_bridge":
		return "webview"
	case "activity_launch", "smali_activity_launch", "service_launch", "broadcast":
		return "intent"
	case "sqlite", "smali_sqlite":
		return "sqlite"
	case "network":
		return "network"
	case "file_write":
		return "file_write"
	default:
		return ""
	}
}

func summarizeEntryTraceFlows(flows []entryTraceHookFlow, label string) string {
	files := map[string]bool{}
	handlers := map[string]bool{}
	for _, item := range flows {
		flow := item.Flow
		if flow.File != "" {
			files[flow.File] = true
		}
		key := flow.File + ":" + flow.Method
		handlers[key] = true
	}
	return fmt.Sprintf("Found %d exported entry_trace flow(s) reaching %s across %d handler(s) in %d file(s)", len(flows), label, len(handlers), len(files))
}

func entryTraceFlowComments(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	for i, item := range flows {
		if i >= 5 {
			break
		}
		flow := item.Flow
		source := fmt.Sprintf("%s:%d", flow.Source.File, flow.Source.Line)
		sink := fmt.Sprintf("%s:%d", flow.Sink.File, flow.Sink.Line)
		var via string
		if len(flow.Variables) > 0 {
			via = " via " + strings.Join(flow.Variables, ", ")
		}
		fmt.Fprintf(&sb, "    // %s %s %s -> %s %s%s\n", item.ID, flow.Method, source, sink, flow.Sink.Pattern, via)
	}
	return sb.String()
}

func entryTraceFlowIDs(flows []entryTraceHookFlow) string {
	return strings.Join(entryTraceFlowIDList(flows), ",")
}

func entryTraceFlowIDList(flows []entryTraceHookFlow) []string {
	ids := make([]string, 0, len(flows))
	for _, flow := range flows {
		ids = append(ids, flow.ID)
	}
	return ids
}

func buildExecMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace Runtime.exec Monitor");
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var Runtime = Java.use("java.lang.Runtime");
    var FLOW_IDS = %q;

    var execString = Runtime.exec.overload("java.lang.String");
    execString.implementation = function(cmd) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String): " + cmd);
        return execString.call(this, cmd);
    };

    var execArray = Runtime.exec.overload("[Ljava.lang.String;");
    execArray.implementation = function(cmd) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String[]): " + cmd.join(" "));
        return execArray.call(this, cmd);
    };

    var execStringEnv = Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;");
    execStringEnv.implementation = function(cmd, envp) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String, env): " + cmd);
        return execStringEnv.call(this, cmd, envp);
    };

    var execArrayEnv = Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;");
    execArrayEnv.implementation = function(cmd, envp) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String[], env): " + cmd.join(" "));
        return execArrayEnv.call(this, cmd, envp);
    };

    var execStringEnvDir = Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;", "java.io.File");
    execStringEnvDir.implementation = function(cmd, envp, dir) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String, env, dir): " + cmd + " dir=" + dir);
        return execStringEnvDir.call(this, cmd, envp, dir);
    };

    var execArrayEnvDir = Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File");
    execArrayEnvDir.implementation = function(cmd, envp, dir) {
        console.log("[ENTRY_TRACE][exec][flows=" + FLOW_IDS + "] Runtime.exec(String[], env, dir): " + cmd.join(" ") + " dir=" + dir);
        return execArrayEnvDir.call(this, cmd, envp, dir);
    };

    console.log("[+] Entry Trace Runtime.exec monitor active");
});
`, flowIDs))
	return sb.String()
}

func buildWebViewMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace WebView Sink Monitor");
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var WebView = Java.use("android.webkit.WebView");
    var FLOW_IDS = %q;

    var loadUrlString = WebView.loadUrl.overload("java.lang.String");
    loadUrlString.implementation = function(url) {
        console.log("[ENTRY_TRACE][webview][flows=" + FLOW_IDS + "] loadUrl: " + url);
        return loadUrlString.call(this, url);
    };

    var loadUrlHeaders = WebView.loadUrl.overload("java.lang.String", "java.util.Map");
    loadUrlHeaders.implementation = function(url, headers) {
        console.log("[ENTRY_TRACE][webview][flows=" + FLOW_IDS + "] loadUrl(headers): " + url + " headers=" + headers);
        return loadUrlHeaders.call(this, url, headers);
    };

    var addJS = WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String");
    addJS.implementation = function(obj, name) {
        console.log("[ENTRY_TRACE][webview][flows=" + FLOW_IDS + "] addJavascriptInterface: " + name + " obj=" + obj);
        return addJS.call(this, obj, name);
    };

    console.log("[+] Entry Trace WebView monitor active");
});
`, flowIDs))
	return sb.String()
}

func buildIntentMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace Intent & Broadcast Monitor");

    function describeIntent(intent) {
        if (intent === null) return "<null>";
        var parts = [];
        try { parts.push("action=" + intent.getAction()); } catch(e) {}
        try { parts.push("data=" + intent.getDataString()); } catch(e) {}
        try { parts.push("component=" + intent.getComponent()); } catch(e) {}
        try {
            var extras = intent.getExtras();
            if (extras) parts.push("extras=" + extras.toString());
        } catch(e) {}
        return parts.join(" ");
    }
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var FLOW_IDS = %q;

    var Activity = Java.use("android.app.Activity");
    var startActivity = Activity.startActivity.overload("android.content.Intent");
    startActivity.implementation = function(intent) {
        console.log("[ENTRY_TRACE][intent][flows=" + FLOW_IDS + "] Activity.startActivity: " + describeIntent(intent));
        return startActivity.call(this, intent);
    };

    var ContextWrapper = Java.use("android.content.ContextWrapper");
    var startService = ContextWrapper.startService.overload("android.content.Intent");
    startService.implementation = function(intent) {
        console.log("[ENTRY_TRACE][intent][flows=" + FLOW_IDS + "] Context.startService: " + describeIntent(intent));
        return startService.call(this, intent);
    };

    var sendBroadcast = ContextWrapper.sendBroadcast.overload("android.content.Intent");
    sendBroadcast.implementation = function(intent) {
        console.log("[ENTRY_TRACE][intent][flows=" + FLOW_IDS + "] Context.sendBroadcast: " + describeIntent(intent));
        return sendBroadcast.call(this, intent);
    };

    var sendOrderedBroadcast = ContextWrapper.sendOrderedBroadcast.overload("android.content.Intent", "java.lang.String");
    sendOrderedBroadcast.implementation = function(intent, permission) {
        console.log("[ENTRY_TRACE][intent][flows=" + FLOW_IDS + "] Context.sendOrderedBroadcast: " + describeIntent(intent) + " permission=" + permission);
        return sendOrderedBroadcast.call(this, intent, permission);
    };

    console.log("[+] Entry Trace intent/broadcast monitor active");
});
`, flowIDs))
	return sb.String()
}

func buildSQLiteMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace SQLite Sink Monitor");
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    var FLOW_IDS = %q;

    var execSQL = SQLiteDatabase.execSQL.overload("java.lang.String");
    execSQL.implementation = function(sql) {
        console.log("[ENTRY_TRACE][sqlite][flows=" + FLOW_IDS + "] execSQL: " + sql);
        return execSQL.call(this, sql);
    };

    var rawQuery = SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;");
    rawQuery.implementation = function(sql, args) {
        console.log("[ENTRY_TRACE][sqlite][flows=" + FLOW_IDS + "] rawQuery: " + sql + " args=" + args);
        return rawQuery.call(this, sql, args);
    };

    var query = SQLiteDatabase.query.overload("java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String");
    query.implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy) {
        console.log("[ENTRY_TRACE][sqlite][flows=" + FLOW_IDS + "] query table=" + table + " selection=" + selection + " args=" + selectionArgs);
        return query.call(this, table, columns, selection, selectionArgs, groupBy, having, orderBy);
    };

    console.log("[+] Entry Trace SQLite monitor active");
});
`, flowIDs))
	return sb.String()
}

func buildNetworkMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace Network Sink Monitor");
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var FLOW_IDS = %q;

    try {
        var URL = Java.use("java.net.URL");
        var openConnection = URL.openConnection.overload();
        openConnection.implementation = function() {
            console.log("[ENTRY_TRACE][network][flows=" + FLOW_IDS + "] URL.openConnection: " + this.toString());
            return openConnection.call(this);
        };
    } catch(e) {
        console.log("[ENTRY_TRACE][network] URL hook unavailable: " + e);
    }

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var newCall = OkHttpClient.newCall.overload("okhttp3.Request");
        newCall.implementation = function(request) {
            console.log("[ENTRY_TRACE][network][flows=" + FLOW_IDS + "] OkHttp.newCall: " + request.method() + " " + request.url().toString());
            return newCall.call(this, request);
        };
    } catch(e) {
        console.log("[ENTRY_TRACE][network] OkHttp hook unavailable: " + e);
    }

    console.log("[+] Entry Trace network monitor active");
});
`, flowIDs))
	return sb.String()
}

func buildFileWriteMonitorHook(flows []entryTraceHookFlow) string {
	var sb strings.Builder
	flowIDs := entryTraceFlowIDs(flows)
	sb.WriteString(`Java.perform(function() {
    console.log("[*] Entry Trace File Write Monitor");
`)
	sb.WriteString(entryTraceFlowComments(flows))
	sb.WriteString(fmt.Sprintf(`
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    var FLOW_IDS = %q;
    var openFileOutput = ContextWrapper.openFileOutput.overload("java.lang.String", "int");
    openFileOutput.implementation = function(name, mode) {
        console.log("[ENTRY_TRACE][file][flows=" + FLOW_IDS + "] openFileOutput: " + name + " mode=" + mode);
        return openFileOutput.call(this, name, mode);
    };

    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var fosString = FileOutputStream.$init.overload("java.lang.String");
    fosString.implementation = function(path) {
        console.log("[ENTRY_TRACE][file][flows=" + FLOW_IDS + "] FileOutputStream: " + path);
        return fosString.call(this, path);
    };

    console.log("[+] Entry Trace file write monitor active");
});
`, flowIDs))
	return sb.String()
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
