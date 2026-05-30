package agent

import (
	"testing"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/runner"
)

func TestRegisterBuiltinsIncludesAPKTriage(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	skill, ok := reg.Get("apk_triage")
	if !ok {
		t.Fatal("expected apk_triage skill to be registered")
	}
	if skill.Description == "" {
		t.Fatal("expected apk_triage to have an LLM-facing description")
	}

	tools := reg.AsLLMTools()
	var found bool
	for _, tool := range tools {
		if tool.Function.Name != "apk_triage" {
			continue
		}
		found = true
		props, ok := tool.Function.Parameters["properties"].(map[string]any)
		if !ok {
			t.Fatalf("expected apk_triage properties schema, got %#v", tool.Function.Parameters["properties"])
		}
		if _, ok := props["apk_id"]; !ok {
			t.Fatal("expected apk_triage schema to require apk_id")
		}
		if _, ok := props["include_callgraph"]; !ok {
			t.Fatal("expected apk_triage schema to expose include_callgraph option")
		}
	}
	if !found {
		t.Fatal("expected apk_triage to be exposed as an LLM tool")
	}

	attackSurface, ok := reg.Get("apk_attack_surface")
	if !ok {
		t.Fatal("expected apk_attack_surface skill to be registered")
	}
	if attackSurface.Description == "" {
		t.Fatal("expected apk_attack_surface to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_attack_surface"); !ok {
		t.Fatal("expected apk_attack_surface metadata")
	}

	entryTrace, ok := reg.Get("apk_entry_trace")
	if !ok {
		t.Fatal("expected apk_entry_trace skill to be registered")
	}
	if entryTrace.Description == "" {
		t.Fatal("expected apk_entry_trace to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_entry_trace"); !ok {
		t.Fatal("expected apk_entry_trace metadata")
	}

	runtimePlan, ok := reg.Get("apk_runtime_plan")
	if !ok {
		t.Fatal("expected apk_runtime_plan skill to be registered")
	}
	if runtimePlan.Description == "" {
		t.Fatal("expected apk_runtime_plan to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_runtime_plan"); !ok {
		t.Fatal("expected apk_runtime_plan metadata")
	}

	evidencePackage, ok := reg.Get("apk_evidence_package")
	if !ok {
		t.Fatal("expected apk_evidence_package skill to be registered")
	}
	if evidencePackage.Description == "" {
		t.Fatal("expected apk_evidence_package to have an LLM-facing description")
	}
	if _, ok := reg.Metadata("apk_evidence_package"); !ok {
		t.Fatal("expected apk_evidence_package metadata")
	}
}

func TestRegisterBuiltinsMarksDangerousTools(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	for _, name := range []string{
		"device_shell",
		"device_install_apk",
		"local_shell",
		"termux_shell",
		"frida_hook",
		"frida_eval",
		"frida_spawn",
		"frida_run_script",
	} {
		if !reg.IsDangerous(name) {
			t.Fatalf("expected %s to be marked dangerous", name)
		}
		meta, ok := reg.Metadata(name)
		if !ok {
			t.Fatalf("expected metadata for %s", name)
		}
		if !meta.Builtin || meta.Source != "builtin" {
			t.Fatalf("expected builtin metadata for %s, got %#v", name, meta)
		}
	}

	for _, name := range []string{
		"apk_triage",
		"apk_attack_surface",
		"apk_entry_trace",
		"apk_strings",
		"apk_callgraph",
		"apk_generate_hooks",
		"apk_runtime_plan",
		"apk_evidence_package",
		"file_read",
		"code_search",
		"device_list",
	} {
		if reg.IsDangerous(name) {
			t.Fatalf("expected %s to stay non-dangerous", name)
		}
	}
}

func TestRegisterBuiltinsIncludesAPKReversePlanValidate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.WorkspaceDir = t.TempDir()
	cfg.Storage.UploadDir = t.TempDir()
	cfg.Skills.ShellMaxOutputBytes = 4096

	reg := NewRegistry()
	RegisterBuiltins(
		reg,
		runner.NewADBRunner(cfg),
		runner.NewAPKRunner(cfg),
		runner.NewFridaRunner(cfg),
		nil,
		nil,
		cfg,
	)

	for _, name := range []string{"apk_reverse_plan", "apk_reverse_validate"} {
		skill, ok := reg.Get(name)
		if !ok {
			t.Fatalf("expected %s skill to be registered", name)
		}
		if skill.Description == "" {
			t.Fatalf("expected %s to have an LLM-facing description", name)
		}
		if reg.IsDangerous(name) {
			t.Fatalf("expected %s to stay non-dangerous", name)
		}
	}
}

