package frida

import (
	"regexp"
	"strings"
)

type RuntimeEvidence struct {
	Summary RuntimeEvidenceSummary `json:"summary"`
	Events  []RuntimeEvent         `json:"events"`
}

type RuntimeEvidenceSummary struct {
	Total         int            `json:"total"`
	EntryTrace    int            `json:"entry_trace"`
	ByKind        map[string]int `json:"by_kind"`
	ByOperation   map[string]int `json:"by_operation"`
	HasEntryTrace bool           `json:"has_entry_trace"`
}

type RuntimeEvent struct {
	Line      int    `json:"line"`
	Raw       string `json:"raw"`
	Tag       string `json:"tag"`
	Kind      string `json:"kind"`
	FlowIDs   []string `json:"flow_ids,omitempty"`
	Operation string `json:"operation,omitempty"`
	Value     string `json:"value,omitempty"`
}

var entryTraceLineRE = regexp.MustCompile(`\[ENTRY_TRACE\]\[([^\]]+)\](?:\[flows=([^\]]*)\])?\s*(.*)$`)

// ParseRuntimeEvidence extracts structured evidence from Frida console output.
// It is intentionally conservative: only explicit [ENTRY_TRACE][kind] lines are
// promoted to evidence so generic Frida logs do not create false positives.
func ParseRuntimeEvidence(output string) RuntimeEvidence {
	out := RuntimeEvidence{
		Summary: RuntimeEvidenceSummary{
			ByKind:      map[string]int{},
			ByOperation: map[string]int{},
		},
	}
	for i, line := range strings.Split(output, "\n") {
		raw := strings.TrimSpace(line)
		if raw == "" {
			continue
		}
		m := entryTraceLineRE.FindStringSubmatch(raw)
		if len(m) != 4 {
			continue
		}
		kind := strings.TrimSpace(m[1])
		flowIDs := splitFlowIDs(m[2])
		message := strings.TrimSpace(m[3])
		operation, value := splitEvidenceMessage(message)
		ev := RuntimeEvent{
			Line:      i + 1,
			Raw:       raw,
			Tag:       "ENTRY_TRACE",
			Kind:      kind,
			FlowIDs:   flowIDs,
			Operation: operation,
			Value:     value,
		}
		out.Events = append(out.Events, ev)
		out.Summary.Total++
		out.Summary.EntryTrace++
		out.Summary.ByKind[kind]++
		if operation != "" {
			out.Summary.ByOperation[operation]++
		}
	}
	out.Summary.HasEntryTrace = out.Summary.EntryTrace > 0
	return out
}

func splitEvidenceMessage(message string) (string, string) {
	if message == "" {
		return "", ""
	}
	idx := strings.Index(message, ":")
	if idx < 0 {
		return message, ""
	}
	return strings.TrimSpace(message[:idx]), strings.TrimSpace(message[idx+1:])
}

func splitFlowIDs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
