package frida

import "testing"

func TestParseRuntimeEvidenceExtractsEntryTraceEvents(t *testing.T) {
	output := `Spawned com.example.app. Resuming main thread!
[*] Entry Trace Runtime.exec Monitor
[ENTRY_TRACE][exec][flows=flow-001] Runtime.exec(String): id
[ENTRY_TRACE][webview][flows=flow-002,flow-003] loadUrl(headers): https://example.test headers={X=1}
[+] Entry Trace Runtime.exec monitor active`

	evidence := ParseRuntimeEvidence(output)
	if evidence.Summary.Total != 2 || evidence.Summary.EntryTrace != 2 || !evidence.Summary.HasEntryTrace {
		t.Fatalf("unexpected summary: %#v", evidence.Summary)
	}
	if evidence.Summary.ByKind["exec"] != 1 || evidence.Summary.ByKind["webview"] != 1 {
		t.Fatalf("unexpected kind buckets: %#v", evidence.Summary.ByKind)
	}
	if evidence.Events[0].Kind != "exec" ||
		evidence.Events[0].Operation != "Runtime.exec(String)" ||
		evidence.Events[0].Value != "id" ||
		len(evidence.Events[0].FlowIDs) != 1 ||
		evidence.Events[0].FlowIDs[0] != "flow-001" {
		t.Fatalf("unexpected first event: %#v", evidence.Events[0])
	}
	if evidence.Events[1].Operation != "loadUrl(headers)" ||
		evidence.Events[1].Value != "https://example.test headers={X=1}" ||
		len(evidence.Events[1].FlowIDs) != 2 ||
		evidence.Events[1].FlowIDs[1] != "flow-003" {
		t.Fatalf("unexpected second event: %#v", evidence.Events[1])
	}
}

func TestParseRuntimeEvidenceSupportsLegacyEntryTraceLines(t *testing.T) {
	evidence := ParseRuntimeEvidence("[ENTRY_TRACE][exec] Runtime.exec(String): id\n")
	if evidence.Summary.Total != 1 {
		t.Fatalf("expected one evidence event, got %#v", evidence)
	}
	if len(evidence.Events[0].FlowIDs) != 0 || evidence.Events[0].Kind != "exec" {
		t.Fatalf("unexpected legacy event: %#v", evidence.Events[0])
	}
}

func TestParseRuntimeEvidenceIgnoresGenericLogs(t *testing.T) {
	evidence := ParseRuntimeEvidence("[CRYPTO] Cipher.getInstance: AES\n[+] loaded\n")
	if evidence.Summary.Total != 0 || len(evidence.Events) != 0 {
		t.Fatalf("expected no evidence, got %#v", evidence)
	}
}
