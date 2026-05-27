package analyzer

import (
	"fmt"
	"sort"
	"strings"
)

type AttackSurfaceResult struct {
	Summary        AttackSurfaceSummary     `json:"summary"`
	EntryPoints    []AttackSurfaceEntry     `json:"entry_points,omitempty"`
	DeepLinks      []DeepLinkSurface        `json:"deep_links,omitempty"`
	ContentURIs    []ContentProviderSurface `json:"content_uris,omitempty"`
	SuggestedTests []SuggestedTestCommand   `json:"suggested_tests,omitempty"`
	Findings       []AttackSurfaceFinding   `json:"findings,omitempty"`
}

type AttackSurfaceSummary struct {
	ExportedActivities int      `json:"exported_activities"`
	ExportedServices   int      `json:"exported_services"`
	ExportedReceivers  int      `json:"exported_receivers"`
	ExportedProviders  int      `json:"exported_providers"`
	DeepLinks          int      `json:"deep_links"`
	AppLinks           int      `json:"app_links"`
	Protected          int      `json:"protected"`
	Unprotected        int      `json:"unprotected"`
	RiskLevel          string   `json:"risk_level"`
	Focus              []string `json:"focus,omitempty"`
}

type AttackSurfaceEntry struct {
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Exported      bool           `json:"exported"`
	ExportedBy    string         `json:"exported_by,omitempty"`
	Permission    string         `json:"permission,omitempty"`
	Authorities   []string       `json:"authorities,omitempty"`
	IntentFilters []IntentFilter `json:"intent_filters,omitempty"`
	Risk          string         `json:"risk"`
	Reason        string         `json:"reason"`
	Commands      []string       `json:"commands,omitempty"`
}

type DeepLinkSurface struct {
	Component  string   `json:"component"`
	Scheme     string   `json:"scheme"`
	Host       string   `json:"host,omitempty"`
	Path       string   `json:"path,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	AutoVerify bool     `json:"auto_verify,omitempty"`
	Command    string   `json:"command,omitempty"`
	Risk       string   `json:"risk"`
}

type ContentProviderSurface struct {
	Provider            string   `json:"provider"`
	Authorities         []string `json:"authorities"`
	Permission          string   `json:"permission,omitempty"`
	ReadPermission      string   `json:"read_permission,omitempty"`
	WritePermission     string   `json:"write_permission,omitempty"`
	GrantURIPermissions bool     `json:"grant_uri_permissions,omitempty"`
	Commands            []string `json:"commands,omitempty"`
	Risk                string   `json:"risk"`
}

type SuggestedTestCommand struct {
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Risk        string `json:"risk"`
}

type AttackSurfaceFinding struct {
	Level     string `json:"level"`
	Code      string `json:"code"`
	Component string `json:"component,omitempty"`
	Summary   string `json:"summary"`
	Evidence  string `json:"evidence,omitempty"`
}

func AnalyzeAttackSurface(m *ManifestResult) *AttackSurfaceResult {
	res := &AttackSurfaceResult{}
	if m == nil {
		res.Summary.RiskLevel = "unknown"
		return res
	}

	addComponents := func(kind string, comps []Component) {
		for _, c := range comps {
			entry, include := buildAttackSurfaceEntry(m.Package, kind, c)
			if !include {
				continue
			}
			res.EntryPoints = append(res.EntryPoints, entry)
			if entry.Permission != "" {
				res.Summary.Protected++
			} else {
				res.Summary.Unprotected++
			}
			switch kind {
			case "activity":
				res.Summary.ExportedActivities++
			case "service":
				res.Summary.ExportedServices++
			case "receiver":
				res.Summary.ExportedReceivers++
			case "provider":
				res.Summary.ExportedProviders++
			}
			res.Findings = append(res.Findings, findingsForEntry(entry)...)
			for _, cmd := range entry.Commands {
				res.SuggestedTests = append(res.SuggestedTests, SuggestedTestCommand{
					Kind:        kind,
					Target:      entry.Name,
					Description: suggestedDescription(kind, entry),
					Command:     cmd,
					Risk:        entry.Risk,
				})
			}
			if kind == "provider" && len(entry.Authorities) > 0 {
				provider := ContentProviderSurface{
					Provider:            entry.Name,
					Authorities:         entry.Authorities,
					Permission:          c.Permission,
					ReadPermission:      c.ReadPermission,
					WritePermission:     c.WritePermission,
					GrantURIPermissions: c.GrantURIPermissions,
					Commands:            entry.Commands,
					Risk:                entry.Risk,
				}
				res.ContentURIs = append(res.ContentURIs, provider)
			}
			for _, dl := range deepLinksForEntry(m.Package, entry, c.IntentFilters) {
				res.DeepLinks = append(res.DeepLinks, dl)
				res.Summary.DeepLinks++
				if dl.AutoVerify {
					res.Summary.AppLinks++
				}
			}
		}
	}

	addComponents("activity", m.Activities)
	addComponents("service", m.Services)
	addComponents("receiver", m.Receivers)
	addComponents("provider", m.Providers)

	sort.Slice(res.EntryPoints, func(i, j int) bool {
		if riskRank(res.EntryPoints[i].Risk) != riskRank(res.EntryPoints[j].Risk) {
			return riskRank(res.EntryPoints[i].Risk) > riskRank(res.EntryPoints[j].Risk)
		}
		if res.EntryPoints[i].Kind != res.EntryPoints[j].Kind {
			return res.EntryPoints[i].Kind < res.EntryPoints[j].Kind
		}
		return res.EntryPoints[i].Name < res.EntryPoints[j].Name
	})
	if len(res.SuggestedTests) > 50 {
		res.SuggestedTests = res.SuggestedTests[:50]
	}
	res.Summary.RiskLevel = attackSurfaceRisk(res)
	res.Summary.Focus = attackSurfaceFocus(res)
	return res
}

func buildAttackSurfaceEntry(pkg, kind string, c Component) (AttackSurfaceEntry, bool) {
	exported, by := componentExported(c)
	if !exported {
		return AttackSurfaceEntry{}, false
	}
	name := normalizeComponentName(pkg, c.Name)
	entry := AttackSurfaceEntry{
		Kind:          kind,
		Name:          name,
		Exported:      true,
		ExportedBy:    by,
		Permission:    componentPermission(c),
		Authorities:   c.Authorities,
		IntentFilters: c.IntentFilters,
	}
	entry.Risk, entry.Reason = classifyEntryRisk(kind, entry, c)
	entry.Commands = commandsForEntry(pkg, kind, name, c)
	return entry, true
}

func componentExported(c Component) (bool, string) {
	if c.Exported != nil {
		if *c.Exported {
			return true, "explicit"
		}
		return false, "explicit_false"
	}
	if len(c.IntentFilters) > 0 {
		return true, "implicit_intent_filter"
	}
	return false, "default_false"
}

func componentPermission(c Component) string {
	if c.Permission != "" {
		return c.Permission
	}
	if c.ReadPermission != "" || c.WritePermission != "" {
		parts := []string{}
		if c.ReadPermission != "" {
			parts = append(parts, "read="+c.ReadPermission)
		}
		if c.WritePermission != "" {
			parts = append(parts, "write="+c.WritePermission)
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func classifyEntryRisk(kind string, entry AttackSurfaceEntry, c Component) (string, string) {
	protected := entry.Permission != ""
	filters := len(c.IntentFilters)
	hasDeepLink := false
	for _, f := range c.IntentFilters {
		if hasBrowsableDeepLink(f) {
			hasDeepLink = true
			break
		}
	}
	switch kind {
	case "provider":
		if !protected {
			return "high", "exported content provider without manifest permission"
		}
		if c.GrantURIPermissions {
			return "medium", "exported provider grants URI permissions; validate path permissions"
		}
		return "medium", "exported content provider protected by manifest permission"
	case "service":
		if !protected {
			return "high", "exported service without manifest permission"
		}
		return "medium", "exported service protected by manifest permission"
	case "receiver":
		if !protected {
			return "medium", "exported broadcast receiver without manifest permission"
		}
		return "low", "exported receiver protected by manifest permission"
	case "activity":
		if hasDeepLink && !protected {
			return "high", "exported browsable deeplink activity without manifest permission"
		}
		if !protected && filters == 0 {
			return "medium", "exported activity without intent filter or manifest permission"
		}
		if !protected {
			return "medium", "exported activity without manifest permission"
		}
		return "low", "exported activity protected by manifest permission"
	default:
		if !protected {
			return "medium", "exported component without manifest permission"
		}
		return "low", "exported component protected by manifest permission"
	}
}

func findingsForEntry(e AttackSurfaceEntry) []AttackSurfaceFinding {
	level := e.Risk
	code := "EXPORTED_COMPONENT"
	if e.Kind == "provider" && e.Permission == "" {
		code = "EXPORTED_PROVIDER_NO_PERMISSION"
	} else if e.Kind == "service" && e.Permission == "" {
		code = "EXPORTED_SERVICE_NO_PERMISSION"
	} else if e.Kind == "activity" && hasDeepLinkFilters(e.IntentFilters) {
		code = "EXPORTED_DEEPLINK_ACTIVITY"
	}
	return []AttackSurfaceFinding{{
		Level:     level,
		Code:      code,
		Component: e.Name,
		Summary:   e.Reason,
		Evidence:  fmt.Sprintf("kind=%s exported_by=%s permission=%s", e.Kind, e.ExportedBy, e.Permission),
	}}
}

func deepLinksForEntry(pkg string, e AttackSurfaceEntry, filters []IntentFilter) []DeepLinkSurface {
	if e.Kind != "activity" {
		return nil
	}
	var out []DeepLinkSurface
	for _, f := range filters {
		if !hasBrowsableDeepLink(f) {
			continue
		}
		actions := f.Actions
		if len(actions) == 0 {
			actions = []string{"android.intent.action.VIEW"}
		}
		schemes := f.Schemes
		if len(schemes) == 0 {
			schemes = []string{""}
		}
		hosts := f.Hosts
		if len(hosts) == 0 {
			hosts = []string{""}
		}
		paths := candidatePaths(f)
		for _, scheme := range schemes {
			for _, host := range hosts {
				for _, path := range paths {
					uri := buildURI(scheme, host, path)
					cmd := ""
					if uri != "" {
						cmd = fmt.Sprintf("adb shell am start -a android.intent.action.VIEW -d '%s' %s", shellSingleQuoteSafe(uri), pkg)
					}
					risk := "medium"
					if !f.AutoVerify && (scheme != "http" && scheme != "https") {
						risk = "high"
					}
					out = append(out, DeepLinkSurface{
						Component:  e.Name,
						Scheme:     scheme,
						Host:       host,
						Path:       path,
						Actions:    actions,
						AutoVerify: f.AutoVerify,
						Command:    cmd,
						Risk:       risk,
					})
				}
			}
		}
	}
	return out
}

func commandsForEntry(pkg, kind, name string, c Component) []string {
	var cmds []string
	component := fmt.Sprintf("%s/%s", pkg, name)
	switch kind {
	case "activity":
		cmds = append(cmds, fmt.Sprintf("adb shell am start -n %s", component))
		for _, f := range c.IntentFilters {
			for _, action := range f.Actions {
				if action == "android.intent.action.MAIN" {
					continue
				}
				cmds = append(cmds, fmt.Sprintf("adb shell am start -a %s -n %s", action, component))
			}
		}
	case "service":
		cmds = append(cmds, fmt.Sprintf("adb shell am startservice -n %s", component))
	case "receiver":
		cmds = append(cmds, fmt.Sprintf("adb shell am broadcast -n %s", component))
		for _, f := range c.IntentFilters {
			for _, action := range f.Actions {
				cmds = append(cmds, fmt.Sprintf("adb shell am broadcast -a %s -n %s", action, component))
			}
		}
	case "provider":
		for _, auth := range c.Authorities {
			cmds = append(cmds, fmt.Sprintf("adb shell content query --uri content://%s/", auth))
		}
	}
	return dedupeAttackSurfaceStrings(cmds)
}

func suggestedDescription(kind string, e AttackSurfaceEntry) string {
	switch kind {
	case "activity":
		return "Launch exported activity/deeplink and observe auth/parameter handling."
	case "service":
		return "Start exported service and verify permission/auth checks."
	case "receiver":
		return "Send broadcast to exported receiver and verify input handling."
	case "provider":
		return "Query exported provider and verify data exposure/path permissions."
	}
	return "Exercise exported component and verify access control."
}

func hasBrowsableDeepLink(f IntentFilter) bool {
	if len(f.Schemes) == 0 && len(f.Hosts) == 0 {
		return false
	}
	if len(f.Categories) == 0 {
		return true
	}
	for _, c := range f.Categories {
		if c == "android.intent.category.BROWSABLE" {
			return true
		}
	}
	return false
}

func hasDeepLinkFilters(filters []IntentFilter) bool {
	for _, f := range filters {
		if hasBrowsableDeepLink(f) {
			return true
		}
	}
	return false
}

func candidatePaths(f IntentFilter) []string {
	paths := []string{}
	paths = append(paths, f.Paths...)
	paths = append(paths, f.PathPrefixes...)
	paths = append(paths, f.PathPatterns...)
	if len(paths) == 0 {
		paths = append(paths, "/")
	}
	return dedupeAttackSurfaceStrings(paths)
}

func buildURI(scheme, host, path string) string {
	if scheme == "" {
		return ""
	}
	if host == "" {
		return scheme + "://" + strings.TrimPrefix(path, "/")
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}

func normalizeComponentName(pkg, name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") {
		return pkg + name
	}
	if strings.Contains(name, ".") {
		return name
	}
	if pkg != "" {
		return pkg + "." + name
	}
	return name
}

func attackSurfaceRisk(res *AttackSurfaceResult) string {
	high := 0
	medium := 0
	for _, e := range res.EntryPoints {
		switch e.Risk {
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	if high >= 3 || res.Summary.ExportedProviders > 0 && res.Summary.Unprotected > 0 {
		return "high"
	}
	if high > 0 || medium >= 3 {
		return "medium"
	}
	if len(res.EntryPoints) > 0 {
		return "low"
	}
	return "none"
}

func attackSurfaceFocus(res *AttackSurfaceResult) []string {
	focus := []string{}
	if res.Summary.ExportedProviders > 0 {
		focus = append(focus, "content providers")
	}
	if res.Summary.DeepLinks > 0 {
		focus = append(focus, "deeplinks/app links")
	}
	if res.Summary.ExportedServices > 0 {
		focus = append(focus, "exported services")
	}
	if res.Summary.ExportedReceivers > 0 {
		focus = append(focus, "broadcast receivers")
	}
	if len(focus) == 0 && len(res.EntryPoints) > 0 {
		focus = append(focus, "exported activities")
	}
	return focus
}

func riskRank(r string) int {
	switch r {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func shellSingleQuoteSafe(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func dedupeAttackSurfaceStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
