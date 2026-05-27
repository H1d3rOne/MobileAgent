package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeEntryTraceFindsDeepLinkInputToSink(t *testing.T) {
	manifest := &ManifestResult{Package: "com.example.app"}
	parseManifestXMLTree(`E: manifest (line=2)
  E: application (line=8)
    E: activity (line=12)
      A: android:name(0x01010003)=".DeepLinkActivity"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=13)
        E: action (line=14)
          A: android:name(0x01010003)="android.intent.action.VIEW"
        E: category (line=15)
          A: android:name(0x01010003)="android.intent.category.BROWSABLE"
        E: data (line=16)
          A: android:scheme(0x01010027)="myapp"
          A: android:host(0x01010028)="open"
`, manifest)

	decompiledDir := t.TempDir()
	srcDir := filepath.Join(decompiledDir, "sources", "com", "example", "app")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "DeepLinkActivity.java"), []byte(`package com.example.app;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;

public class DeepLinkActivity extends Activity {
  WebView webView;
  protected void onCreate(Bundle b) {
    Uri u = getIntent().getData();
    String token = u.getQueryParameter("token");
    webView.loadUrl(token);
  }
}
`), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	res, err := AnalyzeEntryTrace(manifest, decompiledDir, "")
	if err != nil {
		t.Fatalf("AnalyzeEntryTrace: %v", err)
	}
	if res.Summary.Components != 1 {
		t.Fatalf("expected 1 component, got %#v", res.Summary)
	}
	if res.Summary.FilesMatched != 1 {
		t.Fatalf("expected 1 matched file, got %#v", res.Summary)
	}
	if res.Summary.HandlersFound == 0 {
		t.Fatalf("expected handler signal, got %#v", res)
	}
	if res.Summary.InputSignalsFound == 0 {
		t.Fatalf("expected input signals, got %#v", res)
	}
	if res.Summary.SinkSignalsFound == 0 {
		t.Fatalf("expected sink signals, got %#v", res)
	}
	if res.Summary.FlowsFound == 0 {
		t.Fatalf("expected source-to-sink flow, got %#v", res)
	}
	if len(res.Traces) != 1 {
		t.Fatalf("expected one trace, got %#v", res.Traces)
	}
	if res.Traces[0].Risk != "high" && res.Traces[0].Risk != "medium" {
		t.Fatalf("expected high or medium risk, got %#v", res.Traces[0])
	}
	if len(res.Traces[0].Flows) == 0 {
		t.Fatalf("expected trace flow evidence, got %#v", res.Traces[0])
	}
	flow := res.Traces[0].Flows[0]
	if flow.Risk != "high" || flow.Method != "onCreate" || flow.Source.Line == 0 || flow.Sink.Line == 0 {
		t.Fatalf("unexpected flow evidence: %#v", flow)
	}
	if len(flow.Variables) == 0 || flow.Variables[0] != "token" {
		t.Fatalf("expected token to be tracked into sink, got %#v", flow.Variables)
	}
	if len(res.Traces[0].Commands) == 0 {
		t.Fatalf("expected replay command, got %#v", res.Traces[0])
	}
}
