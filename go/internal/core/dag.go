package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type NodeStatus int

const (
	StatusPending NodeStatus = iota
	StatusRunning
	StatusDone
	StatusSkipped
	StatusFallback
	StatusBlocked
	StatusRefused
)

func (s NodeStatus) String() string {
	return []string{"pending", "running", "done", "skip", "fallback", "blocked", "refused"}[s]
}

type Outcome int

const (
	OutcomeClean Outcome = iota
	OutcomeSuccess
	OutcomeRefused
	OutcomeBlocked
	OutcomeChallenge
	OutcomeError
)

type ChainState struct {
	WAFDetected        bool
	AIRefusals         int
	SuccessfulExploits int
	Insights           map[string]string
}

type NodeResult struct {
	Findings []Finding
	Outcome  Outcome
}

type AttackEdge struct {
	FromID   int    `json:"from_id"`
	ToID     int    `json:"to_id"`
	ToName   string `json:"to_name"`
	Findings int    `json:"findings"`
}

type AttackGraph struct {
	Edges        []AttackEdge   `json:"edges"`
	NodeStatus   map[int]string `json:"node_status"`
	NodeFindings map[int]int    `json:"node_findings"`
}

func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		Edges:        []AttackEdge{},
		NodeStatus:   make(map[int]string),
		NodeFindings: make(map[int]int),
	}
}

func (g *AttackGraph) RecordExecution(id int, name string, deps []int, findings int) {
	g.NodeStatus[id] = "executed"
	g.NodeFindings[id] = findings
	for _, dep := range deps {
		g.Edges = append(g.Edges, AttackEdge{
			FromID:   dep,
			ToID:     id,
			ToName:   name,
			Findings: g.NodeFindings[dep],
		})
	}
}

func (g *AttackGraph) RecordSkip(id int) {
	g.NodeStatus[id] = "skipped"
}

func (g *AttackGraph) ToMermaid(nodes map[int][2]string) string {
	var sb strings.Builder
	sb.WriteString("graph TD\n")
	for id, status := range g.NodeStatus {
		namePhase := nodes[id]
		name := namePhase[0]
		phase := namePhase[1]
		findings := g.NodeFindings[id]
		label := fmt.Sprintf("%s\\n[%s] %d findings", name, phase, findings)
		class := "skip"
		switch {
		case status == "executed" && findings > 0:
			class = "hit"
		case status == "executed":
			class = "clean"
		case status == "fallback" && findings > 0:
			class = "fallback_hit"
		case status == "fallback":
			class = "fallback"
		}
		fmt.Fprintf(&sb, "    N%d[\"%s\"]:::%s\n", id, label, class)
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&sb, "    N%d --> N%d\n", e.FromID, e.ToID)
	}
	sb.WriteString("    classDef hit fill:#ff6b6b,stroke:#c92a2a,color:#fff\n")
	sb.WriteString("    classDef clean fill:#51cf66,stroke:#2b8a3e,color:#fff\n")
	sb.WriteString("    classDef skip fill:#adb5bd,stroke:#868e96,color:#fff\n")
	sb.WriteString("    classDef fallback fill:#ffd43b,stroke:#f08c00,color:#000\n")
	sb.WriteString("    classDef fallback_hit fill:#ff922b,stroke:#e8590c,color:#fff\n")
	return sb.String()
}

type ModuleRunner func(target Target, cfg interface{}) ([]Finding, Outcome)

type Node struct {
	ID          int
	Name        string
	Category    string
	Phase       string
	DependsOn   []int
	FallbackFor *int
	Run         ModuleRunner
	Condition   func(results map[int]NodeResult) bool
}

type DAG struct {
	nodes       []Node
	nodeMap     map[int]int
	concurrency int
}

func NewDAG(concurrency int) *DAG {
	if concurrency < 1 {
		concurrency = 1
	}
	return &DAG{
		nodes:       []Node{},
		nodeMap:     make(map[int]int),
		concurrency: concurrency,
	}
}

func (d *DAG) AddNode(n Node) {
	d.nodeMap[n.ID] = len(d.nodes)
	d.nodes = append(d.nodes, n)
}

func (d *DAG) Len() int {
	return len(d.nodes)
}

func (d *DAG) Nodes() []Node {
	return d.nodes
}

func (d *DAG) TopologicalLevels() [][]int {
	inDegree := make(map[int]int)
	children := make(map[int][]int)

	for _, n := range d.nodes {
		if _, ok := inDegree[n.ID]; !ok {
			inDegree[n.ID] = 0
		}
		for _, dep := range n.DependsOn {
			children[dep] = append(children[dep], n.ID)
			inDegree[n.ID]++
		}
	}

	var queue []int
	for _, n := range d.nodes {
		if inDegree[n.ID] == 0 {
			queue = append(queue, n.ID)
		}
	}

	var levels [][]int
	for len(queue) > 0 {
		var levelIndices []int
		var nextQueue []int
		for _, id := range queue {
			if idx, ok := d.nodeMap[id]; ok {
				levelIndices = append(levelIndices, idx)
			}
			for _, kid := range children[id] {
				inDegree[kid]--
				if inDegree[kid] == 0 {
					nextQueue = append(nextQueue, kid)
				}
			}
		}
		levels = append(levels, levelIndices)
		queue = nextQueue
	}
	return levels
}

func (d *DAG) Execute(target Target, cfg interface{}, onProgress func(int, string, NodeStatus)) ([]Finding, *AttackGraph) {
	if len(d.nodes) == 0 {
		return nil, NewAttackGraph()
	}

	fmt.Printf("\n\033[36m[*]\033[0m DAG Attack Chain (%d nodes, concurrency=%d) %s\n", len(d.nodes), d.concurrency, strings.Repeat("═", 30))
	fmt.Printf("\033[36m[*]\033[0m Target: %s\n", target)

	start := time.Now()
	levels := d.TopologicalLevels()

	graph := NewAttackGraph()
	var allFindings []Finding
	var mu sync.Mutex
	completed := make(map[int]bool)
	nodeResults := make(map[int]NodeResult)
	chainState := &ChainState{Insights: make(map[string]string)}
	sem := make(chan struct{}, d.concurrency)

	for levelIdx, level := range levels {
		if len(level) == 0 {
			continue
		}
		fmt.Printf("\n\033[36m[*]\033[0m --- Level %d: %d nodes ---\n", levelIdx, len(level))

		var wg sync.WaitGroup
		for _, idx := range level {
			node := d.nodes[idx]

			wg.Add(1)
			go func(n Node) {
				defer wg.Done()

				mu.Lock()
				skip := false
				depsMet := true
				for _, dep := range n.DependsOn {
					if !completed[dep] {
						depsMet = false
						break
					}
				}
				if !depsMet {
					graph.RecordSkip(n.ID)
					completed[n.ID] = true
					skip = true
				} else if n.FallbackFor != nil {
					if res, ok := nodeResults[*n.FallbackFor]; ok && len(res.Findings) > 0 {
						completed[n.ID] = true
						graph.RecordSkip(n.ID)
						skip = true
					}
				}
				if !skip && n.Condition != nil && !n.Condition(nodeResults) {
					completed[n.ID] = true
					graph.RecordSkip(n.ID)
					skip = true
				}
				mu.Unlock()
				if skip {
					return
				}

				sem <- struct{}{}
				defer func() { <-sem }()

				if onProgress != nil {
					onProgress(n.ID, n.Name, StatusRunning)
				}

				findings, outcome := n.Run(target, cfg)
				count := len(findings)

				mu.Lock()
				switch outcome {
				case OutcomeBlocked:
					if !chainState.WAFDetected {
						fmt.Printf("  \033[33m[!]\033[0m [Insight] WAF detected! Enabling adaptive evasion.\n")
						chainState.WAFDetected = true
					}
				case OutcomeRefused:
					chainState.AIRefusals++
				case OutcomeSuccess:
					chainState.SuccessfulExploits++
				}

				allFindings = append(allFindings, findings...)
				nodeResults[n.ID] = NodeResult{Findings: findings, Outcome: outcome}
				completed[n.ID] = true
				graph.RecordExecution(n.ID, n.Name, n.DependsOn, count)
				mu.Unlock()

				if count > 0 {
					fmt.Printf("  \033[32m[+]\033[0m %s: %d findings\n", n.Name, count)
				}

				status := StatusDone
				switch outcome {
				case OutcomeBlocked:
					status = StatusBlocked
				case OutcomeRefused:
					status = StatusRefused
				}
				if n.FallbackFor != nil && status == StatusDone {
					status = StatusFallback
				}
				if onProgress != nil {
					onProgress(n.ID, n.Name, status)
				}
			}(node)
		}
		wg.Wait()
	}

	elapsed := time.Since(start)
	score := 0
	for _, f := range allFindings {
		score += f.Severity.Score()
	}
	if score > 100 {
		score = 100
	}

	fmt.Printf("\n\033[36m[*]\033[0m DAG chain complete: %d findings, risk score %d/100, %v %s\n",
		len(allFindings), score, elapsed, strings.Repeat("═", 20))

	return allFindings, graph
}

func (d *DAG) ExecuteSingle(id int, target Target, cfg interface{}) []Finding {
	for _, n := range d.nodes {
		if n.ID == id {
			fmt.Printf("\033[36m[*]\033[0m Running single chain: %s (#%d)\n", n.Name, n.ID)
			findings, _ := n.Run(target, cfg)
			return findings
		}
	}
	fmt.Printf("  \033[31m[-]\033[0m Chain #%d not found\n", id)
	return nil
}

func (d *DAG) ExecutePhase(target Target, cfg interface{}, phases []string, onProgress func(int, string, NodeStatus)) ([]Finding, *AttackGraph) {
	phaseSet := make(map[string]bool)
	for _, p := range phases {
		phaseSet[p] = true
	}
	filtered := NewDAG(d.concurrency)
	for _, n := range d.nodes {
		if phaseSet[n.Phase] {
			filtered.AddNode(n)
		}
	}
	return filtered.Execute(target, cfg, onProgress)
}

func HasAnyFinding(results map[int]NodeResult) bool {
	for _, r := range results {
		if len(r.Findings) > 0 {
			return true
		}
	}
	return false
}

func HasCriticalOrHigh(results map[int]NodeResult) bool {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity >= High {
				return true
			}
		}
	}
	return false
}

func NodeHasFindings(results map[int]NodeResult, id int) bool {
	r, ok := results[id]
	return ok && len(r.Findings) > 0
}
