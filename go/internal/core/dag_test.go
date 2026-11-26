package core

import (
	"testing"
)

func TestTopologicalLevelsOrder(t *testing.T) {
	d := NewDAG(2)
	d.AddNode(Node{ID: 0, Name: "root", Run: func(Target, interface{}) ([]Finding, Outcome) { return nil, OutcomeClean }})
	d.AddNode(Node{ID: 1, Name: "child", DependsOn: []int{0}, Run: func(Target, interface{}) ([]Finding, Outcome) { return nil, OutcomeClean }})
	d.AddNode(Node{ID: 2, Name: "peer", Run: func(Target, interface{}) ([]Finding, Outcome) { return nil, OutcomeClean }})

	levels := d.TopologicalLevels()
	if len(levels) < 2 {
		t.Fatalf("levels = %d, want at least 2", len(levels))
	}
	level0 := map[int]bool{}
	for _, idx := range levels[0] {
		level0[d.nodes[idx].ID] = true
	}
	if !level0[0] || !level0[2] {
		t.Fatalf("level 0 ids = %v, want 0 and 2", keys(level0))
	}
	if len(levels[1]) != 1 || d.nodes[levels[1][0]].ID != 1 {
		t.Fatalf("level 1 = %v, want node 1", levels[1])
	}
}

func TestExecuteRunsDependenciesBeforeChild(t *testing.T) {
	var order []int
	run := func(id int) ModuleRunner {
		return func(Target, interface{}) ([]Finding, Outcome) {
			order = append(order, id)
			return nil, OutcomeClean
		}
	}
	d := NewDAG(1)
	d.AddNode(Node{ID: 0, Name: "a", Run: run(0)})
	d.AddNode(Node{ID: 1, Name: "b", DependsOn: []int{0}, Run: run(1)})

	findings, graph := d.Execute(Target{Host: "127.0.0.1", Port: 9}, nil, nil)
	if len(findings) != 0 {
		t.Fatalf("findings = %d", len(findings))
	}
	if len(order) != 2 || order[0] != 0 || order[1] != 1 {
		t.Fatalf("order = %v, want [0 1]", order)
	}
	if graph.NodeStatus[0] != "executed" || graph.NodeStatus[1] != "executed" {
		t.Fatalf("status = %#v", graph.NodeStatus)
	}
}

func TestExecuteSkipsFallbackWhenParentHits(t *testing.T) {
	parent := 0
	fb := 0
	d := NewDAG(1)
	d.AddNode(Node{
		ID: 0, Name: "parent",
		Run: func(Target, interface{}) ([]Finding, Outcome) {
			return []Finding{NewFinding("t", "p", "hit", High, "x")}, OutcomeSuccess
		},
	})
	d.AddNode(Node{
		ID: 1, Name: "fallback", FallbackFor: &fb, DependsOn: []int{parent},
		Run: func(Target, interface{}) ([]Finding, Outcome) {
			t.Fatal("fallback must not run")
			return nil, OutcomeClean
		},
	})
	findings, graph := d.Execute(Target{Host: "127.0.0.1", Port: 9}, nil, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if graph.NodeStatus[1] != "skipped" {
		t.Fatalf("fallback status = %q", graph.NodeStatus[1])
	}
}

func TestExecuteSingleMissing(t *testing.T) {
	d := NewDAG(1)
	d.AddNode(Node{ID: 3, Name: "only", Run: func(Target, interface{}) ([]Finding, Outcome) { return nil, OutcomeClean }})
	if got := d.ExecuteSingle(99, Target{}, nil); got != nil {
		t.Fatalf("got %#v", got)
	}
}

func TestHasCriticalOrHigh(t *testing.T) {
	results := map[int]NodeResult{
		1: {Findings: []Finding{NewFinding("t", "m", "n", Medium, "d")}},
	}
	if HasCriticalOrHigh(results) {
		t.Fatal("medium must not count")
	}
	results[2] = NodeResult{Findings: []Finding{NewFinding("t", "m", "n", High, "d")}}
	if !HasCriticalOrHigh(results) {
		t.Fatal("high must count")
	}
}

func keys(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	return out
}
