package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobileagent/backend-go/internal/llm"
)

// Plan is the structured task plan produced by the Plan phase.
type Plan struct {
	Goal  string     `json:"goal"`
	Steps []PlanStep `json:"steps"`
}

type PlanStep struct {
	Index  int      `json:"index"`
	Desc   string   `json:"desc"`
	Skills []string `json:"skills,omitempty"`
	Status string   `json:"status,omitempty"` // pending|running|ok|deviated|blocked|new_finding|done
}

// StepOutcome is emitted by the LLM when a step's ReAct sub-loop finishes.
type StepOutcome struct {
	Status string `json:"status"` // ok|deviated|blocked|new_finding
	Note   string `json:"note"`
}

// ReplanDecision adjusts the remaining steps after a deviation.
type ReplanDecision struct {
	Reason   string     `json:"reason"`
	NewSteps []PlanStep `json:"new_steps"`
	Abort    bool       `json:"abort"`
}

// FinalEval is the completeness self-assessment after all steps run.
type FinalEval struct {
	Complete bool     `json:"complete"`
	Missing  []string `json:"missing,omitempty"`
	Replan   bool     `json:"replan"`
	Summary  string   `json:"summary,omitempty"`
}

// makePlan asks the LLM to decompose the task into ordered steps.
func makePlan(ctx context.Context, client *llm.Client, system, userMessage, skillNames string, missing []string) (Plan, error) {
	var b strings.Builder
	b.WriteString("You are the PLAN phase of an agent. Decompose the user's task into an ordered list of steps.\n")
	b.WriteString("Each step is one coherent unit of work (it may use several tools). Keep steps minimal — do not pad.\n")
	b.WriteString("Available skills: ")
	b.WriteString(skillNames)
	b.WriteString("\n")
	if len(missing) > 0 {
		b.WriteString("\nA previous attempt left these items unaddressed; plan to cover them:\n")
		for _, m := range missing {
			fmt.Fprintf(&b, "- %s\n", m)
		}
	}
	b.WriteString("\nRespond with ONLY a JSON object, no prose:\n")
	b.WriteString(`{"goal":"<one-line goal>","steps":[{"index":0,"desc":"<what to do>","skills":["<skill>"]}]}`)

	messages := []llm.Message{
		{Role: "system", Content: system},
		{Role: "user", Content: userMessage},
		{Role: "user", Content: b.String()},
	}
	out, err := completeJSON(ctx, client, messages)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		return Plan{}, fmt.Errorf("plan parse: %w (raw: %s)", err, truncate(out, 200))
	}
	for i := range p.Steps {
		p.Steps[i].Index = i
		if p.Steps[i].Status == "" {
			p.Steps[i].Status = "pending"
		}
	}
	return p, nil
}

// makeReplan adjusts the remaining steps after a step deviated/blocked.
func makeReplan(ctx context.Context, client *llm.Client, system string, plan Plan, cursor int, outcome StepOutcome) (ReplanDecision, error) {
	planJSON, _ := json.Marshal(plan)
	var b strings.Builder
	b.WriteString("You are the REPLAN phase. Step ")
	fmt.Fprintf(&b, "%d", cursor)
	b.WriteString(" finished with an unexpected outcome. Decide how to adjust the remaining steps.\n")
	fmt.Fprintf(&b, "Current plan: %s\n", planJSON)
	fmt.Fprintf(&b, "Step %d outcome: status=%s, note=%s\n", cursor, outcome.Status, outcome.Note)
	b.WriteString("\nReturn ONLY JSON. new_steps REPLACES all steps after the current one (provide the full remaining list):\n")
	b.WriteString(`{"reason":"<why>","abort":false,"new_steps":[{"desc":"<step>","skills":["<skill>"]}]}`)

	messages := []llm.Message{
		{Role: "system", Content: system},
		{Role: "user", Content: b.String()},
	}
	out, err := completeJSON(ctx, client, messages)
	if err != nil {
		return ReplanDecision{}, err
	}
	var d ReplanDecision
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return ReplanDecision{}, fmt.Errorf("replan parse: %w (raw: %s)", err, truncate(out, 200))
	}
	return d, nil
}

// makeFinalEval asks the LLM whether the task is complete.
func makeFinalEval(ctx context.Context, client *llm.Client, system, userMessage string, history []llm.Message) (FinalEval, error) {
	var b strings.Builder
	b.WriteString("You are the FINAL phase. Assess whether the user's original task is fully complete.\n")
	fmt.Fprintf(&b, "Original task: %s\n", userMessage)
	b.WriteString("\nReturn ONLY JSON. Set replan=true ONLY if meaningful work remains:\n")
	b.WriteString(`{"complete":true,"missing":[],"replan":false,"summary":"<short summary>"}`)

	messages := append([]llm.Message{{Role: "system", Content: system}}, history...)
	messages = append(messages, llm.Message{Role: "user", Content: b.String()})
	out, err := completeJSON(ctx, client, messages)
	if err != nil {
		return FinalEval{}, err
	}
	var e FinalEval
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		return FinalEval{}, fmt.Errorf("final parse: %w (raw: %s)", err, truncate(out, 200))
	}
	return e, nil
}

// completeJSON runs a non-tool LLM completion and returns the extracted JSON string.
func completeJSON(ctx context.Context, client *llm.Client, messages []llm.Message) (string, error) {
	asst, _, err := client.StreamChat(ctx, messages, nil, func(llm.StreamEvent) error { return nil })
	if err != nil {
		return "", err
	}
	return extractJSON(asst.Content), nil
}

// extractJSON pulls the first balanced JSON object out of an LLM response,
// tolerating ```json fences and surrounding prose.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		rest = strings.TrimPrefix(rest, "json")
		rest = strings.TrimPrefix(rest, "JSON")
		if j := strings.Index(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		s = strings.TrimSpace(rest)
	}
	start := strings.Index(s, "{")
	if start < 0 {
		return s
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return s[start:]
}
