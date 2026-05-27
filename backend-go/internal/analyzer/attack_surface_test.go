package analyzer

import "testing"

func TestAnalyzeAttackSurfaceParsesDeepLinksProvidersAndCommands(t *testing.T) {
	manifest := &ManifestResult{Package: "com.example.app"}
	parseManifestXMLTree(`E: manifest (line=2)
  E: application (line=8)
    E: activity (line=12)
      A: android:name(0x01010003)=".DeepLinkActivity"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: intent-filter (line=13)
        A: android:autoVerify(0x010105ee)=(type 0x12)0xffffffff
        E: action (line=14)
          A: android:name(0x01010003)="android.intent.action.VIEW"
        E: category (line=15)
          A: android:name(0x01010003)="android.intent.category.BROWSABLE"
        E: data (line=16)
          A: android:scheme(0x01010027)="https"
          A: android:host(0x01010028)="example.test"
          A: android:pathPrefix(0x0101002a)="/open"
    E: service (line=30)
      A: android:name(0x01010003)="com.example.app.SyncService"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
    E: provider (line=40)
      A: android:name(0x01010003)=".PublicProvider"
      A: android:authorities(0x01010018)="com.example.app.public;com.example.app.files"
      A: android:exported(0x01010010)=(type 0x12)0xffffffff
`, manifest)

	res := AnalyzeAttackSurface(manifest)
	if res.Summary.ExportedActivities != 1 {
		t.Fatalf("expected 1 exported activity, got %#v", res.Summary)
	}
	if res.Summary.ExportedServices != 1 {
		t.Fatalf("expected 1 exported service, got %#v", res.Summary)
	}
	if res.Summary.ExportedProviders != 1 {
		t.Fatalf("expected 1 exported provider, got %#v", res.Summary)
	}
	if res.Summary.DeepLinks != 1 || res.Summary.AppLinks != 1 {
		t.Fatalf("expected one verified deeplink, got %#v", res.Summary)
	}
	if res.Summary.RiskLevel != "high" {
		t.Fatalf("expected high risk level, got %#v", res.Summary.RiskLevel)
	}
	if len(res.DeepLinks) != 1 {
		t.Fatalf("expected one deeplink, got %#v", res.DeepLinks)
	}
	if got := res.DeepLinks[0].Command; got != "adb shell am start -a android.intent.action.VIEW -d 'https://example.test/open' com.example.app" {
		t.Fatalf("unexpected deeplink command: %q", got)
	}
	if len(res.ContentURIs) != 1 || len(res.ContentURIs[0].Authorities) != 2 {
		t.Fatalf("expected provider authorities, got %#v", res.ContentURIs)
	}
	if len(res.SuggestedTests) == 0 {
		t.Fatal("expected suggested adb tests")
	}
	var hasProviderQuery bool
	for _, test := range res.SuggestedTests {
		if test.Command == "adb shell content query --uri content://com.example.app.public/" {
			hasProviderQuery = true
		}
	}
	if !hasProviderQuery {
		t.Fatalf("expected provider query command, got %#v", res.SuggestedTests)
	}
}

func TestAnalyzeAttackSurfaceTreatsImplicitIntentFilterAsExported(t *testing.T) {
	manifest := &ManifestResult{Package: "com.example.app"}
	parseManifestXMLTree(`E: manifest (line=2)
  E: application (line=8)
    E: receiver (line=20)
      A: android:name(0x01010003)=".BootReceiver"
      E: intent-filter (line=21)
        E: action (line=22)
          A: android:name(0x01010003)="android.intent.action.BOOT_COMPLETED"
`, manifest)

	res := AnalyzeAttackSurface(manifest)
	if res.Summary.ExportedReceivers != 1 {
		t.Fatalf("expected implicit exported receiver, got %#v", res.Summary)
	}
	if len(res.EntryPoints) != 1 || res.EntryPoints[0].ExportedBy != "implicit_intent_filter" {
		t.Fatalf("expected implicit export entry, got %#v", res.EntryPoints)
	}
}
