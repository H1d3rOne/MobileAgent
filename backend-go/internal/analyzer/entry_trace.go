package analyzer

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type EntryTraceResult struct {
	Package string            `json:"package"`
	Summary EntryTraceSummary `json:"summary"`
	Traces  []EntryTrace      `json:"traces,omitempty"`
}

type EntryTraceSummary struct {
	Components        int    `json:"components"`
	FilesMatched      int    `json:"files_matched"`
	HandlersFound     int    `json:"handlers_found"`
	InputSignalsFound int    `json:"input_signals_found"`
	SinkSignalsFound  int    `json:"sink_signals_found"`
	FlowsFound        int    `json:"flows_found"`
	RiskLevel         string `json:"risk_level"`
}

type EntryTrace struct {
	Kind        string            `json:"kind"`
	Component   string            `json:"component"`
	Risk        string            `json:"risk"`
	Reason      string            `json:"reason,omitempty"`
	SourceFiles []EntrySourceFile `json:"source_files,omitempty"`
	Handlers    []EntrySignal     `json:"handlers,omitempty"`
	Inputs      []EntrySignal     `json:"inputs,omitempty"`
	Sinks       []EntrySignal     `json:"sinks,omitempty"`
	Flows       []EntryFlow       `json:"flows,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

type EntrySourceFile struct {
	File     string `json:"file"`
	Language string `json:"language"`
}

type EntrySignal struct {
	Kind     string `json:"kind"`
	Pattern  string `json:"pattern"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Evidence string `json:"evidence,omitempty"`
}

type EntryFlow struct {
	File      string      `json:"file"`
	Method    string      `json:"method,omitempty"`
	Source    EntrySignal `json:"source"`
	Sink      EntrySignal `json:"sink"`
	Variables []string    `json:"variables,omitempty"`
	Risk      string      `json:"risk"`
	Reason    string      `json:"reason,omitempty"`
}

type entryTraceTarget struct {
	Kind      string
	Component string
	Commands  []string
}

type entryTraceLine struct {
	No       int
	Text     string
	Trimmed  string
	Handlers []EntrySignal
	Inputs   []EntrySignal
	Sinks    []EntrySignal
}

var (
	reJavaHandler  = regexp.MustCompile(`\b(onCreate|onNewIntent|onStartCommand|onBind|onReceive|query|insert|update|delete|openFile|getType|call|attachInfo)\s*\(`)
	reSmaliHandler = regexp.MustCompile(`^\.method\s+.*\s(onCreate|onNewIntent|onStartCommand|onBind|onReceive|query|insert|update|delete|openFile|getType|call|attachInfo)\(`)
)

var entryInputPatterns = []struct {
	kind    string
	pattern string
}{
	{"intent", "getIntent"},
	{"intent_data", "getData"},
	{"intent_extra", "getStringExtra"},
	{"intent_extra", "getExtras"},
	{"uri_param", "getQueryParameter"},
	{"uri", "Uri.parse"},
	{"bundle", "Bundle"},
	{"content_provider_args", "selection"},
	{"content_provider_args", "projection"},
	{"content_provider_args", "sortOrder"},
	{"smali_intent", "Landroid/content/Intent;->getData"},
	{"smali_intent_extra", "Landroid/content/Intent;->getStringExtra"},
	{"smali_uri_param", "Landroid/net/Uri;->getQueryParameter"},
	{"smali_bundle", "Landroid/os/Bundle;"},
}

var entrySinkPatterns = []struct {
	kind    string
	pattern string
}{
	{"activity_launch", "startActivity"},
	{"service_launch", "startService"},
	{"broadcast", "sendBroadcast"},
	{"command_exec", "Runtime.getRuntime().exec"},
	{"webview", "loadUrl"},
	{"webview_bridge", "addJavascriptInterface"},
	{"file_write", "openFileOutput"},
	{"sqlite", "SQLiteDatabase"},
	{"network", "HttpURLConnection"},
	{"network", "OkHttpClient"},
	{"log", "Log."},
	{"smali_activity_launch", "Landroid/content/Context;->startActivity"},
	{"smali_command_exec", "Ljava/lang/Runtime;->exec"},
	{"smali_webview", "Landroid/webkit/WebView;->loadUrl"},
	{"smali_sqlite", "Landroid/database/sqlite/SQLiteDatabase;"},
	{"smali_log", "Landroid/util/Log;"},
}

func AnalyzeEntryTrace(m *ManifestResult, decompiledPath, componentFilter string) (*EntryTraceResult, error) {
	res := &EntryTraceResult{}
	if m == nil {
		res.Summary.RiskLevel = "unknown"
		return res, nil
	}
	res.Package = m.Package

	targets := entryTraceTargets(m, componentFilter)
	for _, target := range targets {
		trace := EntryTrace{Kind: target.Kind, Component: target.Component, Commands: target.Commands}
		files, err := findComponentSourceFiles(decompiledPath, target.Component)
		if err != nil {
			return res, err
		}
		if len(files) == 0 {
			trace.Risk = "unknown"
			trace.Reason = "component source file not found in decompiled artifacts"
			trace.Notes = append(trace.Notes, "Try decompiling with the other tool (jadx/apktool), then rerun entry_trace.")
			res.Traces = append(res.Traces, trace)
			continue
		}
		for _, f := range files {
			trace.SourceFiles = append(trace.SourceFiles, EntrySourceFile{File: f.rel, Language: languageForFile(f.rel)})
			handlers, inputs, sinks, flows := scanEntryTraceFile(f.abs, f.rel)
			trace.Handlers = append(trace.Handlers, handlers...)
			trace.Inputs = append(trace.Inputs, inputs...)
			trace.Sinks = append(trace.Sinks, sinks...)
			trace.Flows = append(trace.Flows, flows...)
		}
		capSignals(&trace.Handlers, 30)
		capSignals(&trace.Inputs, 50)
		capSignals(&trace.Sinks, 50)
		capFlows(&trace.Flows, 50)
		trace.Risk, trace.Reason = classifyEntryTraceRisk(trace)
		res.Traces = append(res.Traces, trace)
	}

	res.Summary.Components = len(res.Traces)
	for _, tr := range res.Traces {
		res.Summary.FilesMatched += len(tr.SourceFiles)
		res.Summary.HandlersFound += len(tr.Handlers)
		res.Summary.InputSignalsFound += len(tr.Inputs)
		res.Summary.SinkSignalsFound += len(tr.Sinks)
		res.Summary.FlowsFound += len(tr.Flows)
	}
	res.Summary.RiskLevel = entryTraceOverallRisk(res.Traces)
	return res, nil
}

func entryTraceTargets(m *ManifestResult, componentFilter string) []entryTraceTarget {
	attack := AnalyzeAttackSurface(m)
	commandByKey := map[string][]string{}
	for _, e := range attack.EntryPoints {
		commandByKey[e.Kind+":"+e.Name] = e.Commands
	}
	var targets []entryTraceTarget
	add := func(kind string, comps []Component) {
		for _, c := range comps {
			name := normalizeComponentName(m.Package, c.Name)
			if componentFilter != "" {
				if !componentMatches(name, componentFilter) {
					continue
				}
			} else if exported, _ := componentExported(c); !exported {
				continue
			}
			targets = append(targets, entryTraceTarget{Kind: kind, Component: name, Commands: commandByKey[kind+":"+name]})
		}
	}
	add("activity", m.Activities)
	add("service", m.Services)
	add("receiver", m.Receivers)
	add("provider", m.Providers)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Kind != targets[j].Kind {
			return targets[i].Kind < targets[j].Kind
		}
		return targets[i].Component < targets[j].Component
	})
	return targets
}

func componentMatches(name, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" || name == filter {
		return true
	}
	return strings.HasSuffix(name, "."+filter) || strings.Contains(name, filter)
}

type traceFile struct {
	abs string
	rel string
}

func findComponentSourceFiles(root, component string) ([]traceFile, error) {
	if root == "" || component == "" {
		return nil, nil
	}
	classPath := strings.ReplaceAll(component, ".", "/")
	simple := component
	if i := strings.LastIndex(simple, "."); i >= 0 {
		simple = simple[i+1:]
	}
	var out []traceFile
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "build" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".smali" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		match := strings.HasSuffix(relSlash, classPath+ext)
		if !match && simple != "" {
			match = strings.HasSuffix(relSlash, "/"+simple+ext) || relSlash == simple+ext
		}
		if !match {
			return nil
		}
		if !seen[relSlash] {
			seen[relSlash] = true
			out = append(out, traceFile{abs: path, rel: relSlash})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	if len(out) > 20 {
		out = out[:20]
	}
	return out, nil
}

func scanEntryTraceFile(abs, rel string) (handlers, inputs, sinks []EntrySignal, flows []EntryFlow) {
	info, err := os.Stat(abs)
	if err != nil || info.Size() > maxFileSize {
		return nil, nil, nil, nil
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, nil, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	var lines []entryTraceLine
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		rec := entryTraceLine{No: lineNo, Text: line, Trimmed: trimmed}
		if m := reJavaHandler.FindStringSubmatch(line); len(m) > 1 {
			sig := EntrySignal{Kind: "handler", Pattern: m[1], File: rel, Line: lineNo, Evidence: trimValue(trimmed)}
			handlers = append(handlers, sig)
			rec.Handlers = append(rec.Handlers, sig)
		}
		if m := reSmaliHandler.FindStringSubmatch(trimmed); len(m) > 1 {
			sig := EntrySignal{Kind: "handler", Pattern: m[1], File: rel, Line: lineNo, Evidence: trimValue(trimmed)}
			handlers = append(handlers, sig)
			rec.Handlers = append(rec.Handlers, sig)
		}
		for _, p := range entryInputPatterns {
			if strings.Contains(line, p.pattern) {
				sig := EntrySignal{Kind: p.kind, Pattern: p.pattern, File: rel, Line: lineNo, Evidence: trimValue(trimmed)}
				inputs = append(inputs, sig)
				rec.Inputs = append(rec.Inputs, sig)
			}
		}
		for _, p := range entrySinkPatterns {
			if strings.Contains(line, p.pattern) {
				sig := EntrySignal{Kind: p.kind, Pattern: p.pattern, File: rel, Line: lineNo, Evidence: trimValue(trimmed)}
				sinks = append(sinks, sig)
				rec.Sinks = append(rec.Sinks, sig)
			}
		}
		lines = append(lines, rec)
	}
	flows = inferEntryFlows(rel, lines)
	return handlers, inputs, sinks, flows
}

func inferEntryFlows(rel string, lines []entryTraceLine) []EntryFlow {
	var handlerIdx []int
	for i, line := range lines {
		if len(line.Handlers) > 0 {
			handlerIdx = append(handlerIdx, i)
		}
	}
	if len(handlerIdx) == 0 {
		return nil
	}
	var flows []EntryFlow
	seen := map[string]bool{}
	for i, start := range handlerIdx {
		end := len(lines)
		if i+1 < len(handlerIdx) {
			end = handlerIdx[i+1]
		}
		method := lines[start].Handlers[0].Pattern
		for _, flow := range inferFlowsInRegion(rel, method, lines[start:end]) {
			key := fmt.Sprintf("%s:%d:%d:%s", flow.File, flow.Source.Line, flow.Sink.Line, strings.Join(flow.Variables, ","))
			if seen[key] {
				continue
			}
			seen[key] = true
			flows = append(flows, flow)
		}
	}
	return flows
}

func inferFlowsInRegion(rel, method string, lines []entryTraceLine) []EntryFlow {
	tainted := map[string]EntrySignal{}
	var flows []EntryFlow
	for _, line := range lines {
		assigned := assignedVariable(line.Text)
		if len(line.Inputs) > 0 {
			src := line.Inputs[0]
			if assigned != "" {
				tainted[assigned] = src
			}
			for _, param := range providerArgumentNames(method, line.Text) {
				tainted[param] = src
			}
		}
		if assigned != "" {
			for variable, src := range tainted {
				if variable != assigned && containsIdentifier(line.Text, variable) {
					tainted[assigned] = src
					break
				}
			}
		}
		for _, sink := range line.Sinks {
			if len(line.Inputs) > 0 {
				flows = append(flows, buildEntryFlow(rel, method, line.Inputs[0], sink, nil))
			}
			var variables []string
			var source EntrySignal
			for variable, src := range tainted {
				if containsIdentifier(line.Text, variable) {
					variables = append(variables, variable)
					if source.Line == 0 || src.Line < source.Line {
						source = src
					}
				}
			}
			if source.Line != 0 {
				sort.Strings(variables)
				flows = append(flows, buildEntryFlow(rel, method, source, sink, variables))
			}
		}
	}
	if len(flows) > 50 {
		flows = flows[:50]
	}
	return flows
}

func buildEntryFlow(rel, method string, source, sink EntrySignal, variables []string) EntryFlow {
	risk := "medium"
	if isHighImpactSink(sink) {
		risk = "high"
	}
	reason := "external input reaches sink inside exported entry handler"
	if len(variables) > 0 {
		reason = fmt.Sprintf("%s via %s", reason, strings.Join(variables, ", "))
	}
	return EntryFlow{
		File:      rel,
		Method:    method,
		Source:    source,
		Sink:      sink,
		Variables: variables,
		Risk:      risk,
		Reason:    reason,
	}
}

func assignedVariable(line string) string {
	before, _, ok := strings.Cut(line, "=")
	if !ok || strings.HasSuffix(strings.TrimSpace(before), "!") || strings.HasSuffix(strings.TrimSpace(before), "=") {
		return ""
	}
	before = strings.TrimSpace(before)
	before = strings.TrimPrefix(before, "final ")
	before = strings.TrimPrefix(before, "var ")
	before = strings.TrimPrefix(before, "val ")
	fields := strings.Fields(before)
	if len(fields) == 0 {
		return ""
	}
	candidate := fields[len(fields)-1]
	candidate = strings.Trim(candidate, " \t\n\r;(){}[]")
	if candidate == "" || !isIdentifier(candidate) {
		return ""
	}
	return candidate
}

func providerArgumentNames(method, line string) []string {
	switch method {
	case "query", "insert", "update", "delete", "openFile", "getType", "call":
	default:
		return nil
	}
	var out []string
	for _, name := range []string{"uri", "projection", "selection", "selectionArgs", "sortOrder", "values", "mode", "method", "arg", "extras"} {
		if containsIdentifier(line, name) {
			out = append(out, name)
		}
	}
	return out
}

func containsIdentifier(line, ident string) bool {
	if ident == "" {
		return false
	}
	idx := strings.Index(line, ident)
	for idx >= 0 {
		beforeOK := idx == 0 || !isIdentifierRune(rune(line[idx-1]))
		afterIdx := idx + len(ident)
		afterOK := afterIdx >= len(line) || !isIdentifierRune(rune(line[afterIdx]))
		if beforeOK && afterOK {
			return true
		}
		next := strings.Index(line[idx+len(ident):], ident)
		if next < 0 {
			break
		}
		idx += len(ident) + next
	}
	return false
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
			continue
		}
		if !isIdentifierRune(r) {
			return false
		}
	}
	return true
}

func isIdentifierRune(r rune) bool {
	return r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
}

func classifyEntryTraceRisk(t EntryTrace) (string, string) {
	if len(t.SourceFiles) == 0 {
		return "unknown", "source file missing"
	}
	if len(t.Flows) > 0 {
		for _, f := range t.Flows {
			if f.Risk == "high" {
				return "high", "external input reaches a high-impact sink inside an entry handler"
			}
		}
		return "medium", "external input reaches sink calls inside entry handlers"
	}
	if len(t.Inputs) > 0 && hasHighImpactSink(t.Sinks) {
		return "high", "entrypoint reads external input and reaches high-impact APIs"
	}
	if len(t.Inputs) > 0 && len(t.Sinks) > 0 {
		return "medium", "entrypoint reads external input and reaches sinks that need review"
	}
	if len(t.Inputs) > 0 {
		return "medium", "entrypoint reads external input"
	}
	if len(t.Sinks) > 0 {
		return "low", "entrypoint contains sink calls but no obvious external input was detected"
	}
	return "info", "no obvious input or sink signal detected in matched source files"
}

func hasHighImpactSink(sinks []EntrySignal) bool {
	for _, s := range sinks {
		if isHighImpactSink(s) {
			return true
		}
	}
	return false
}

func isHighImpactSink(s EntrySignal) bool {
	switch s.Kind {
	case "command_exec", "smali_command_exec", "webview_bridge", "webview", "smali_webview", "sqlite", "smali_sqlite", "network":
		return true
	default:
		return false
	}
}

func entryTraceOverallRisk(traces []EntryTrace) string {
	level := "none"
	for _, t := range traces {
		if riskRank(t.Risk) > riskRank(level) {
			level = t.Risk
		}
	}
	return level
}

func capSignals(items *[]EntrySignal, max int) {
	if len(*items) > max {
		*items = (*items)[:max]
	}
}

func capFlows(items *[]EntryFlow, max int) {
	if len(*items) > max {
		*items = (*items)[:max]
	}
}

func languageForFile(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".java":
		return "java"
	case ".kt":
		return "kotlin"
	case ".smali":
		return "smali"
	default:
		return fmt.Sprintf("%s", strings.TrimPrefix(filepath.Ext(path), "."))
	}
}
