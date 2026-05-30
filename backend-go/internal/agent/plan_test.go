package agent

import "testing"

func TestExtractJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", `{"a":1}`, `{"a":1}`},
		{"fenced", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"fenced_no_lang", "```\n{\"a\":1}\n```", `{"a":1}`},
		{"prose_prefix", `Here is the plan: {"a":1}`, `{"a":1}`},
		{"nested", `{"a":{"b":2},"c":3}`, `{"a":{"b":2},"c":3}`},
		{"brace_in_string", `{"a":"x}y"}`, `{"a":"x}y"}`},
		{"escaped_quote", `{"a":"x\"}y"}`, `{"a":"x\"}y"}`},
		{"trailing_prose", `{"a":1} done`, `{"a":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractJSON(c.in); got != c.want {
				t.Errorf("extractJSON(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSpliceSteps(t *testing.T) {
	steps := []PlanStep{
		{Index: 0, Desc: "a"},
		{Index: 1, Desc: "b"},
		{Index: 2, Desc: "c"},
	}
	newSteps := []PlanStep{{Desc: "x"}, {Desc: "y"}}

	got := spliceSteps(steps, 1, newSteps, 20)

	wantDescs := []string{"a", "b", "x", "y"}
	if len(got) != len(wantDescs) {
		t.Fatalf("len = %d, want %d", len(got), len(wantDescs))
	}
	for i, w := range wantDescs {
		if got[i].Desc != w {
			t.Errorf("step[%d].Desc = %q, want %q", i, got[i].Desc, w)
		}
		if got[i].Index != i {
			t.Errorf("step[%d].Index = %d, want %d", i, got[i].Index, i)
		}
		if got[i].Status != "pending" && i >= 2 {
			t.Errorf("new step[%d].Status = %q, want pending", i, got[i].Status)
		}
	}
}

func TestSpliceStepsCap(t *testing.T) {
	steps := []PlanStep{{Index: 0, Desc: "a"}}
	newSteps := make([]PlanStep, 10)
	got := spliceSteps(steps, 0, newSteps, 3)
	if len(got) != 3 {
		t.Errorf("len = %d, want 3 (capped)", len(got))
	}
}
