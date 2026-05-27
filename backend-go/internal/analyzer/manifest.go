package analyzer

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func ParseManifest(apkPath string) (*ManifestResult, error) {
	out, err := exec.Command("aapt", "dump", "badging", apkPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("aapt dump badging: %w\n%s", err, string(out))
	}
	res := &ManifestResult{}
	parseBadging(string(out), res)

	xmlOut, err := exec.Command("aapt", "dump", "xmltree", apkPath, "AndroidManifest.xml").CombinedOutput()
	if err == nil {
		parseManifestXMLTree(string(xmlOut), res)
	}

	if permOut, err := exec.Command("aapt", "dump", "permissions", apkPath).CombinedOutput(); err == nil {
		parsePermissions(string(permOut), res)
	}

	return res, nil
}

var (
	reKV       = regexp.MustCompile(`(\w+)='([^']*)'`)
	reAttrLine = regexp.MustCompile(`A: ([\w\-:]+)\s*\(.*?\)\s*=(.*)`)
)

func parseBadging(text string, res *ManifestResult) {
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "package:"):
			for _, m := range reKV.FindAllStringSubmatch(line, -1) {
				switch m[1] {
				case "name":
					res.Package = m[2]
				case "versionName":
					res.VersionName = m[2]
				case "versionCode":
					if v, err := strconv.Atoi(m[2]); err == nil {
						res.VersionCode = v
					}
				}
			}
		case strings.HasPrefix(line, "sdkVersion:"):
			if v, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(line, "sdkVersion:"), "'")); err == nil {
				res.MinSDK = v
			}
		case strings.HasPrefix(line, "targetSdkVersion:"):
			if v, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(line, "targetSdkVersion:"), "'")); err == nil {
				res.TargetSDK = v
			}
		case strings.HasPrefix(line, "uses-permission:"):
			for _, m := range reKV.FindAllStringSubmatch(line, -1) {
				if m[1] == "name" {
					res.Permissions = appendUnique(res.Permissions, m[2])
				}
			}
		case strings.HasPrefix(line, "launchable-activity:"):
			for _, m := range reKV.FindAllStringSubmatch(line, -1) {
				if m[1] == "name" {
					res.LauncherActivity = m[2]
				}
			}
		}
	}
}

func parsePermissions(text string, res *ManifestResult) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "uses-permission: name=") {
			name := strings.Trim(strings.TrimPrefix(line, "uses-permission: name="), "'")
			res.Permissions = appendUnique(res.Permissions, name)
		}
	}
}

func parseManifestXMLTree(text string, res *ManifestResult) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	type frame struct {
		tag    string
		indent int
		comp   *Component
		filter *IntentFilter
	}
	var stack []frame

	depth := func(line string) int {
		n := 0
		for _, ch := range line {
			if ch == ' ' {
				n++
			} else {
				break
			}
		}
		return n
	}

	attrOf := func(line, key string) (string, bool) {
		for _, m := range reAttrLine.FindAllStringSubmatch(line, -1) {
			if m[1] == key {
				return cleanAttrValue(m[2]), true
			}
		}
		return "", false
	}

	appendToNearestFilter := func(fn func(*IntentFilter)) {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].filter != nil {
				fn(stack[i].filter)
				return
			}
		}
	}
	markNearestComponentLauncher := func() {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].comp != nil {
				stack[i].comp.IsLauncher = true
				return
			}
		}
	}
	applyDataAttrs := func(line string) {
		appendToNearestFilter(func(f *IntentFilter) {
			if v, ok := attrOf(line, "android:scheme"); ok {
				f.Schemes = appendUnique(f.Schemes, v)
			}
			if v, ok := attrOf(line, "android:host"); ok {
				f.Hosts = appendUnique(f.Hosts, v)
			}
			if v, ok := attrOf(line, "android:port"); ok {
				f.Ports = appendUnique(f.Ports, v)
			}
			if v, ok := attrOf(line, "android:path"); ok {
				f.Paths = appendUnique(f.Paths, v)
			}
			if v, ok := attrOf(line, "android:pathPrefix"); ok {
				f.PathPrefixes = appendUnique(f.PathPrefixes, v)
			}
			if v, ok := attrOf(line, "android:pathPattern"); ok {
				f.PathPatterns = appendUnique(f.PathPatterns, v)
			}
			if v, ok := attrOf(line, "android:mimeType"); ok {
				f.MimeTypes = appendUnique(f.MimeTypes, v)
			}
		})
	}
	finishFrame := func(top frame) {
		if top.filter != nil {
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].comp != nil {
					stack[i].comp.IntentFilters = append(stack[i].comp.IntentFilters, *top.filter)
					break
				}
			}
		}
		if top.comp != nil {
			switch top.tag {
			case "activity", "activity-alias":
				res.Activities = append(res.Activities, *top.comp)
			case "service":
				res.Services = append(res.Services, *top.comp)
			case "receiver":
				res.Receivers = append(res.Receivers, *top.comp)
			case "provider":
				res.Providers = append(res.Providers, *top.comp)
			}
		}
	}

	for scanner.Scan() {
		raw := scanner.Text()
		trim := strings.TrimSpace(raw)
		if trim == "" {
			continue
		}
		ind := depth(raw)

		for len(stack) > 0 && stack[len(stack)-1].indent >= ind && (strings.HasPrefix(trim, "E:") || strings.HasPrefix(trim, "N:")) {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			finishFrame(top)
		}

		switch {
		case strings.HasPrefix(trim, "E: application "):
			stack = append(stack, frame{tag: "application", indent: ind})
		case strings.HasPrefix(trim, "E: activity "),
			strings.HasPrefix(trim, "E: activity-alias "),
			strings.HasPrefix(trim, "E: service "),
			strings.HasPrefix(trim, "E: receiver "),
			strings.HasPrefix(trim, "E: provider "):
			tag := strings.Fields(trim)[1]
			comp := &Component{}
			if v, ok := attrOf(trim, "android:name"); ok {
				comp.Name = v
			}
			stack = append(stack, frame{tag: tag, indent: ind, comp: comp})
		case strings.HasPrefix(trim, "E: intent-filter "):
			filter := &IntentFilter{}
			if v, ok := attrOf(trim, "android:autoVerify"); ok {
				filter.AutoVerify = attrBool(v)
			}
			stack = append(stack, frame{tag: "intent-filter", indent: ind, filter: filter})
		case strings.HasPrefix(trim, "E: action "):
			if v, ok := attrOf(trim, "android:name"); ok {
				appendToNearestFilter(func(f *IntentFilter) { f.Actions = appendUnique(f.Actions, v) })
			}
			stack = append(stack, frame{tag: "action", indent: ind})
		case strings.HasPrefix(trim, "E: category "):
			if v, ok := attrOf(trim, "android:name"); ok {
				appendToNearestFilter(func(f *IntentFilter) { f.Categories = appendUnique(f.Categories, v) })
				if v == "android.intent.category.LAUNCHER" {
					markNearestComponentLauncher()
				}
			}
			stack = append(stack, frame{tag: "category", indent: ind})
		case strings.HasPrefix(trim, "E: data "):
			applyDataAttrs(trim)
			stack = append(stack, frame{tag: "data", indent: ind})
		case strings.HasPrefix(trim, "A: "):
			if len(stack) == 0 {
				continue
			}
			top := &stack[len(stack)-1]
			val := cleanAttrValueLine(trim)
			switch top.tag {
			case "action":
				if strings.Contains(trim, "android:name") {
					appendToNearestFilter(func(f *IntentFilter) { f.Actions = appendUnique(f.Actions, val) })
				}
			case "category":
				if strings.Contains(trim, "android:name") {
					appendToNearestFilter(func(f *IntentFilter) { f.Categories = appendUnique(f.Categories, val) })
					if val == "android.intent.category.LAUNCHER" {
						markNearestComponentLauncher()
					}
				}
			case "data":
				if strings.Contains(trim, "android:scheme") {
					appendToNearestFilter(func(f *IntentFilter) { f.Schemes = appendUnique(f.Schemes, val) })
				}
				if strings.Contains(trim, "android:host") {
					appendToNearestFilter(func(f *IntentFilter) { f.Hosts = appendUnique(f.Hosts, val) })
				}
				if strings.Contains(trim, "android:port") {
					appendToNearestFilter(func(f *IntentFilter) { f.Ports = appendUnique(f.Ports, val) })
				}
				if strings.Contains(trim, "android:pathPattern") {
					appendToNearestFilter(func(f *IntentFilter) { f.PathPatterns = appendUnique(f.PathPatterns, val) })
				} else if strings.Contains(trim, "android:pathPrefix") {
					appendToNearestFilter(func(f *IntentFilter) { f.PathPrefixes = appendUnique(f.PathPrefixes, val) })
				} else if strings.Contains(trim, "android:path") {
					appendToNearestFilter(func(f *IntentFilter) { f.Paths = appendUnique(f.Paths, val) })
				}
				if strings.Contains(trim, "android:mimeType") {
					appendToNearestFilter(func(f *IntentFilter) { f.MimeTypes = appendUnique(f.MimeTypes, val) })
				}
			case "intent-filter":
				if strings.Contains(trim, "android:autoVerify") {
					top.filter.AutoVerify = attrBool(val)
				}
			case "activity", "activity-alias", "service", "receiver", "provider":
				if top.comp == nil {
					continue
				}
				switch {
				case strings.Contains(trim, "android:name") && top.comp.Name == "":
					top.comp.Name = val
				case strings.Contains(trim, "android:exported"):
					b := attrBool(val)
					top.comp.Exported = &b
				case strings.Contains(trim, "android:readPermission"):
					top.comp.ReadPermission = val
				case strings.Contains(trim, "android:writePermission"):
					top.comp.WritePermission = val
				case strings.Contains(trim, "android:permission"):
					top.comp.Permission = val
				case strings.Contains(trim, "android:authorities"):
					top.comp.Authorities = splitAuthorities(val)
				case strings.Contains(trim, "android:grantUriPermissions"):
					top.comp.GrantURIPermissions = attrBool(val)
				}
			case "application":
				switch {
				case strings.Contains(trim, "android:debuggable"):
					res.Debuggable = attrBool(val)
				case strings.Contains(trim, "android:allowBackup"):
					res.AllowBackup = attrBool(val)
				case strings.Contains(trim, "android:usesCleartextTraffic"):
					res.UsesCleartextTraffic = attrBool(val)
				case strings.Contains(trim, "android:networkSecurityConfig"):
					res.NetworkSecurityCfg = val
				}
			}
		}
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		finishFrame(top)
	}
}

func attrBool(v string) bool {
	return v == "true" || v == "0xffffffff" || v == "-1"
}

func splitAuthorities(v string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = appendUnique(out, part)
		}
	}
	return out
}

func cleanAttrValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "\""); i >= 0 {
		end := strings.LastIndex(raw, "\"")
		if end > i {
			return raw[i+1 : end]
		}
	}
	if strings.HasPrefix(raw, "(type ") {
		// e.g. (type 0x10)0xffffffff
		if j := strings.LastIndex(raw, ")"); j >= 0 && j+1 < len(raw) {
			return raw[j+1:]
		}
	}
	return raw
}

func cleanAttrValueLine(trim string) string {
	parts := strings.SplitN(trim, "=", 2)
	if len(parts) < 2 {
		return ""
	}
	return cleanAttrValue(parts[1])
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
