package analyzer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func SummarizeRuntimeEvidenceJSON(raw string, maxEvents int) (map[string]any, []string, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, nil, false
	}
	return SummarizeRuntimeEvidencePayload(payload, maxEvents)
}

func SummarizeRuntimeEvidencePayload(payload map[string]any, maxEvents int) (map[string]any, []string, bool) {
	evidence := runtimeMap(payload["evidence"])
	summary := runtimeMap(evidence["summary"])
	events := runtimeList(evidence["events"])
	total := runtimeInt(summary["total"])
	if total == 0 && len(events) == 0 {
		return nil, nil, false
	}
	entryTrace := runtimeInt(summary["entry_trace"])
	byKind := runtimeStringIntMap(summary["by_kind"])

	flowSet := map[string]bool{}
	details := make([]string, 0, maxEvents)
	sample := make([]map[string]any, 0, maxEvents)
	for i, rawEvent := range events {
		if maxEvents > 0 && i >= maxEvents {
			break
		}
		event := runtimeMap(rawEvent)
		kind := fmt.Sprint(event["kind"])
		op := fmt.Sprint(event["operation"])
		value := fmt.Sprint(event["value"])
		flowIDs := runtimeStringList(event["flow_ids"])
		for _, id := range flowIDs {
			flowSet[id] = true
		}
		flowLabel := ""
		if len(flowIDs) > 0 {
			flowLabel = " flows=" + strings.Join(flowIDs, ",")
		}
		detail := fmt.Sprintf("[%s]%s %s", kind, flowLabel, op)
		if value != "" && value != "<nil>" {
			detail += ": " + value
		}
		details = append(details, detail)
		sample = append(sample, map[string]any{
			"kind":      kind,
			"operation": op,
			"value":     value,
			"flow_ids":  flowIDs,
			"raw":       event["raw"],
		})
	}

	flowIDs := make([]string, 0, len(flowSet))
	for id := range flowSet {
		flowIDs = append(flowIDs, id)
	}
	sort.Strings(flowIDs)

	out := map[string]any{
		"total":       total,
		"entry_trace": entryTrace,
		"by_kind":     byKind,
		"flow_ids":    flowIDs,
		"events":      sample,
	}
	if v := payload["serial"]; v != nil {
		out["serial"] = v
	}
	if v := payload["target"]; v != nil {
		out["target"] = v
	}
	if v := payload["hook_id"]; v != nil {
		out["hook_id"] = v
	}
	if v := payload["created_at"]; v != nil {
		out["created_at"] = v
	}
	return out, details, true
}

func RuntimeEvidenceReportSection(summary map[string]any, details []string) ReportSection {
	total := runtimeInt(summary["total"])
	flows := runtimeStringList(summary["flow_ids"])
	verified := runtimeList(summary["verified_flows"])
	flowText := ""
	if len(flows) > 0 {
		flowText = fmt.Sprintf(" across %d flow(s)", len(flows))
	}
	if len(verified) > 0 {
		for _, raw := range verified {
			flow := runtimeMap(raw)
			source := runtimeMap(flow["source"])
			sink := runtimeMap(flow["sink"])
			details = append(details, fmt.Sprintf("verified %s %s.%s %s:%v -> %s:%v (%s)",
				flow["flow_id"], flow["component"], flow["method"],
				source["kind"], source["line"], sink["kind"], sink["line"], sink["pattern"]))
		}
	}
	return ReportSection{
		Title:    "Runtime Entry Trace Evidence",
		Status:   "info",
		Summary:  fmt.Sprintf("Observed %d runtime ENTRY_TRACE hit(s)%s", total, flowText),
		Details:  details,
		Category: "DYNAMIC",
	}
}

func RuntimeEvidenceVerifiedFlows(summary map[string]any, runtimePlanRaw string, maxFlows int) []map[string]any {
	var plan map[string]any
	if err := json.Unmarshal([]byte(runtimePlanRaw), &plan); err != nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, id := range runtimeStringList(summary["flow_ids"]) {
		wanted[id] = true
	}
	if len(wanted) == 0 {
		return nil
	}
	eventsByFlow := map[string][]map[string]any{}
	for _, rawEvent := range runtimeList(summary["events"]) {
		event := runtimeMap(rawEvent)
		for _, id := range runtimeStringList(event["flow_ids"]) {
			eventsByFlow[id] = append(eventsByFlow[id], event)
		}
	}
	out := []map[string]any{}
	for _, rawFlow := range runtimeList(plan["flows"]) {
		flow := runtimeMap(rawFlow)
		flowID := fmt.Sprint(flow["flow_id"])
		if !wanted[flowID] {
			continue
		}
		out = append(out, map[string]any{
			"flow_id":    flowID,
			"component":  flow["component"],
			"kind":       flow["kind"],
			"method":     flow["method"],
			"file":       flow["file"],
			"risk":       flow["risk"],
			"reason":     flow["reason"],
			"source":     flow["source"],
			"sink":       flow["sink"],
			"variables":  flow["variables"],
			"hit_events": eventsByFlow[flowID],
		})
		if maxFlows > 0 && len(out) >= maxFlows {
			break
		}
	}
	return out
}

func runtimeMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]any{}
}

func runtimeList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if l, ok := v.([]interface{}); ok {
		return l
	}
	if l, ok := v.([]map[string]any); ok {
		out := make([]any, 0, len(l))
		for _, item := range l {
			out = append(out, item)
		}
		return out
	}
	if l, ok := v.([]map[string]interface{}); ok {
		out := make([]any, 0, len(l))
		for _, item := range l {
			out = append(out, item)
		}
		return out
	}
	return nil
}

func runtimeStringList(v any) []string {
	if l, ok := v.([]string); ok {
		return l
	}
	items := runtimeList(v)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := strings.TrimSpace(fmt.Sprint(item))
		if s != "" && s != "<nil>" {
			out = append(out, s)
		}
	}
	return out
}

func runtimeStringIntMap(v any) map[string]int {
	m := runtimeMap(v)
	out := map[string]int{}
	for k, val := range m {
		out[k] = runtimeInt(val)
	}
	return out
}

func runtimeInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	default:
		return 0
	}
}
