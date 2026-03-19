package chain

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍ATT&CK phase constants
const (
	PhaseRecon       = "reconnaissance"
	PhaseInitAccess  = "initial-access"
	PhaseExecution   = "execution"
	PhasePersistence = "persistence"
	PhasePrivEsc     = "privilege-escalation"
	PhaseCredAccess  = "credential-access"
	PhaseLateral     = "lateral-movement"
	PhaseCollection  = "collection"
	PhaseExfil       = "exfiltration"
	PhaseImpact      = "impact"
)

// ChainNode represents a single attack step in the DAG
type ChainNode struct {
	ID          int
	Name        string
	Execute     func(target utils.Target, cfg ChainConfig) []utils.Finding
	DependsOn   []int                      // node IDs this depends on
	Condition   func([]utils.Finding) bool // optional: only run if condition met
	Category    string                     // e.g. "auth", "injection", "recon"
	Severity    string                     // expected max severity
	Phase       string                     // ATT&CK phase
	FallbackFor int                        // if >0, this node is a fallback for the specified node ID
}

// AttackEdge represents a triggered dependency edge in the attack graph
type AttackEdge struct {
	FromID   int    `json:"from_id"`
	ToID     int    `json:"to_id"`
	FromName string `json:"from_name"`
	ToName   string `json:"to_name"`
	Findings int    `json:"findings"`
}

// AttackGraph tracks which paths were actually triggered during execution
type AttackGraph struct {
	Edges        []AttackEdge   `json:"edges"`
	NodeStatus   map[int]string `json:"node_status"`
	NodeFindings map[int]int    `json:"node_findings"`
	mu           sync.Mutex
}

// NewAttackGraph creates a new attack graph tracker
func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		NodeStatus:   make(map[int]string),
		NodeFindings: make(map[int]int),
	}
}

// RecordExecution records that a node was executed with the given finding count
func (g *AttackGraph) RecordExecution(node *ChainNode, findings int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.NodeStatus[node.ID] = "executed"
	g.NodeFindings[node.ID] = findings
	for _, depID := range node.DependsOn {
		g.Edges = append(g.Edges, AttackEdge{
			FromID: depID, ToID: node.ID,
			ToName: node.Name, Findings: g.NodeFindings[depID],
		})
	}
}

// RecordSkip records that a node was skipped
func (g *AttackGraph) RecordSkip(nodeID int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.NodeStatus[nodeID] = "skipped"
}

// RecordFallback records that a node ran as a fallback
func (g *AttackGraph) RecordFallback(node *ChainNode, findings int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.NodeStatus[node.ID] = "fallback"
	g.NodeFindings[node.ID] = findings
	for _, depID := range node.DependsOn {
		g.Edges = append(g.Edges, AttackEdge{
			FromID: depID, ToID: node.ID,
			ToName: node.Name, Findings: g.NodeFindings[depID],
		})
	}
}

// ToMermaid generates a Mermaid flowchart of the attack graph
func (g *AttackGraph) ToMermaid(nodeMap map[int]*ChainNode) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	var sb strings.Builder
	sb.WriteString("graph TD\n")

	for id, status := range g.NodeStatus {
		name := fmt.Sprintf("Node%d", id)
		phase := ""
		if n, ok := nodeMap[id]; ok {
			name = n.Name
			phase = n.Phase
		}
		findings := g.NodeFindings[id]
		label := fmt.Sprintf("%s\\n[%s] %d findings", name, phase, findings)

		switch {
		case status == "executed" && findings > 0:
			sb.WriteString(fmt.Sprintf("    N%d[\"%s\"]:::hit\n", id, label))
		case status == "executed":
			sb.WriteString(fmt.Sprintf("    N%d[\"%s\"]:::clean\n", id, label))
		case status == "fallback" && findings > 0:
			sb.WriteString(fmt.Sprintf("    N%d[\"%s\"]:::fallback_hit\n", id, label))
		case status == "fallback":
			sb.WriteString(fmt.Sprintf("    N%d[\"%s\"]:::fallback\n", id, label))
		default:
			sb.WriteString(fmt.Sprintf("    N%d[\"%s\"]:::skip\n", id, label))
		}
	}

	for _, e := range g.Edges {
		sb.WriteString(fmt.Sprintf("    N%d --> N%d\n", e.FromID, e.ToID))
	}

	sb.WriteString("    classDef hit fill:#ff6b6b,stroke:#c92a2a,color:#fff\n")
	sb.WriteString("    classDef clean fill:#51cf66,stroke:#2b8a3e,color:#fff\n")
	sb.WriteString("    classDef skip fill:#adb5bd,stroke:#868e96,color:#fff\n")
	sb.WriteString("    classDef fallback fill:#ffd43b,stroke:#f08c00,color:#000\n")
	sb.WriteString("    classDef fallback_hit fill:#ff922b,stroke:#e8590c,color:#fff\n")
	return sb.String()
}

// ChainScore computes an aggregate risk score (0-100) from findings
func ChainScore(findings []utils.Finding) int {
	score := 0
	for _, f := range findings {
		switch f.Severity {
		case utils.SevCritical:
			score += 25
		case utils.SevHigh:
			score += 15
		case utils.SevMedium:
			score += 8
		case utils.SevLow:
			score += 3
		case utils.SevInfo:
			score += 1
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// DAGChain orchestrates attack chains using a directed acyclic graph
type DAGChain struct {
	Nodes       []*ChainNode
	Concurrency int
	Aggressive  bool
	Graph       *AttackGraph
	nodeMap     map[int]*ChainNode
}

// NewDAGChain creates a DAG-based attack chain orchestrator
func NewDAGChain(concurrency int, aggressive bool) *DAGChain {
	if concurrency < 1 {
		concurrency = 1
	}
	if aggressive && concurrency < 10 {
		concurrency = 10
	}
	return &DAGChain{
		Concurrency: concurrency,
		Aggressive:  aggressive,
		Graph:       NewAttackGraph(),
		nodeMap:     make(map[int]*ChainNode),
	}
}

// AddNode adds an attack step to the DAG
func (d *DAGChain) AddNode(node *ChainNode) {
	d.Nodes = append(d.Nodes, node)
	d.nodeMap[node.ID] = node
}

// Execute runs the DAG with topological ordering and parallel execution
func (d *DAGChain) Execute(target utils.Target, cfg ChainConfig) []utils.Finding {
	if len(d.Nodes) == 0 {
		return nil
	}

	fmt.Printf("\n[*] ═══ DAG Attack Chain (%d nodes, concurrency=%d, aggressive=%v) ═══\n",
		len(d.Nodes), d.Concurrency, d.Aggressive)
	fmt.Printf("[*] Target: %s\n", target.String())

	start := time.Now()

	var (
		allFindings []utils.Finding
		mu          sync.Mutex
		completed   = make(map[int]bool)
		nodeResults = make(map[int][]utils.Finding)
		sem         = make(chan struct{}, d.Concurrency)
	)

	levels := d.topologicalLevels()

	for levelIdx, level := range levels {
		if len(level) == 0 {
			continue
		}

		fmt.Printf("\n[*] --- Level %d: %d nodes ---\n", levelIdx, len(level))

		var wg sync.WaitGroup
		for _, node := range level {
			// Check if dependencies are met
			depsMet := true
			for _, depID := range node.DependsOn {
				if !completed[depID] {
					depsMet = false
					break
				}
			}
			if !depsMet {
				fmt.Printf("  [!] Skipping %s (unmet dependencies)\n", node.Name)
				d.Graph.RecordSkip(node.ID)
				continue
			}

			// Check fallback: skip if parent succeeded
			if node.FallbackFor > 0 {
				mu.Lock()
				parentFindings := nodeResults[node.FallbackFor]
				mu.Unlock()
				if len(parentFindings) > 0 {
					fmt.Printf("  [~] Skipping fallback %s (parent #%d succeeded)\n", node.Name, node.FallbackFor)
					mu.Lock()
					completed[node.ID] = true
					mu.Unlock()
					d.Graph.RecordSkip(node.ID)
					continue
				}
			}

			// Check condition if set
			if node.Condition != nil {
				var depFindings []utils.Finding
				mu.Lock()
				for _, depID := range node.DependsOn {
					depFindings = append(depFindings, nodeResults[depID]...)
				}
				mu.Unlock()
				if !node.Condition(depFindings) {
					fmt.Printf("  [~] Skipping %s (condition not met)\n", node.Name)
					mu.Lock()
					completed[node.ID] = true
					mu.Unlock()
					d.Graph.RecordSkip(node.ID)
					continue
				}
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(n *ChainNode) {
				defer wg.Done()
				defer func() { <-sem }()

				phase := n.Phase
				if phase == "" {
					phase = "?"
				}
				fmt.Printf("  [>] Running: %s (chain #%d) [%s]\n", n.Name, n.ID, phase)
				findings := n.Execute(target, cfg)

				mu.Lock()
				allFindings = append(allFindings, findings...)
				nodeResults[n.ID] = findings
				completed[n.ID] = true
				mu.Unlock()

				if n.FallbackFor > 0 {
					d.Graph.RecordFallback(n, len(findings))
				} else {
					d.Graph.RecordExecution(n, len(findings))
				}

				if len(findings) > 0 {
					fmt.Printf("  [+] %s: %d findings\n", n.Name, len(findings))
				}
			}(node)
		}
		wg.Wait()
	}

	elapsed := time.Since(start)
	score := ChainScore(allFindings)
	fmt.Printf("\n[*] ═══ DAG chain complete: %d findings, risk score %d/100, %s ═══\n",
		len(allFindings), score, elapsed.Round(time.Millisecond))
	return allFindings
}

// topologicalLevels groups nodes into execution levels using Kahn's algorithm
func (d *DAGChain) topologicalLevels() [][]*ChainNode {
	inDegree := make(map[int]int)
	children := make(map[int][]int)

	for _, node := range d.Nodes {
		if _, ok := inDegree[node.ID]; !ok {
			inDegree[node.ID] = 0
		}
		for _, dep := range node.DependsOn {
			children[dep] = append(children[dep], node.ID)
			inDegree[node.ID]++
		}
	}

	var levels [][]*ChainNode
	var queue []int

	for _, node := range d.Nodes {
		if inDegree[node.ID] == 0 {
			queue = append(queue, node.ID)
		}
	}

	for len(queue) > 0 {
		var level []*ChainNode
		var nextQueue []int

		for _, id := range queue {
			if node, ok := d.nodeMap[id]; ok {
				level = append(level, node)
			}
			for _, childID := range children[id] {
				inDegree[childID]--
				if inDegree[childID] == 0 {
					nextQueue = append(nextQueue, childID)
				}
			}
		}

		levels = append(levels, level)
		queue = nextQueue
	}

	return levels
}

// ExecuteSingle runs a single chain node by ID (for targeted exploit)
func (d *DAGChain) ExecuteSingle(target utils.Target, cfg ChainConfig, chainID int) []utils.Finding {
	node, ok := d.nodeMap[chainID]
	if !ok {
		fmt.Printf("  [-] Chain #%d not found\n", chainID)
		return nil
	}
	fmt.Printf("[*] Running single chain: %s (#%d)\n", node.Name, node.ID)
	return node.Execute(target, cfg)
}

// ExecuteCategory runs all chains matching given categories
func (d *DAGChain) ExecuteCategory(target utils.Target, cfg ChainConfig, categories ...string) []utils.Finding {
	catSet := make(map[string]bool)
	for _, c := range categories {
		catSet[c] = true
	}

	filtered := NewDAGChain(d.Concurrency, d.Aggressive)
	for _, node := range d.Nodes {
		if catSet[node.Category] {
			filtered.AddNode(node)
		}
	}
	return filtered.Execute(target, cfg)
}

// ExecutePhase runs all chains matching given ATT&CK phases
func (d *DAGChain) ExecutePhase(target utils.Target, cfg ChainConfig, phases ...string) []utils.Finding {
	phaseSet := make(map[string]bool)
	for _, p := range phases {
		phaseSet[p] = true
	}

	filtered := NewDAGChain(d.Concurrency, d.Aggressive)
	for _, node := range d.Nodes {
		if phaseSet[node.Phase] {
			filtered.AddNode(node)
		}
	}
	return filtered.Execute(target, cfg)
}

// HasFindingWithSeverity checks if findings contain at least one with given severity
func HasFindingWithSeverity(findings []utils.Finding, sev utils.Severity) bool {
	for _, f := range findings {
		if f.Severity >= sev {
			return true
		}
	}
	return false
}

// HasAnyFinding returns true if there are any findings
func HasAnyFinding(findings []utils.Finding) bool {
	return len(findings) > 0
}

// HasCriticalOrHigh checks if findings contain CRITICAL or HIGH severity
func HasCriticalOrHigh(findings []utils.Finding) bool {
	return HasFindingWithSeverity(findings, utils.SevHigh)
}

// HasFindingInCategory checks if findings contain any from the given category (by module name)
func HasFindingInCategory(findings []utils.Finding, category string) bool {
	cat := strings.ToLower(category)
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Module), cat) {
			return true
		}
	}
	return false
}

// NodeProgress reports the status of a single DAG node execution.
type NodeProgress struct {
	NodeID  int
	Name    string
	Phase   string
	Status  string // "pending", "running", "done", "skip", "fallback", "error"
	Elapsed time.Duration
}

// ExecuteWithProgress runs the DAG with context cancellation and progress callbacks.
func (d *DAGChain) ExecuteWithProgress(ctx context.Context, target utils.Target, cfg ChainConfig, onProgress func(NodeProgress), onFinding func(utils.Finding)) []utils.Finding {
	if len(d.Nodes) == 0 {
		return nil
	}

	for _, node := range d.Nodes {
		if onProgress != nil {
			onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "pending"})
		}
	}

	var (
		allFindings []utils.Finding
		mu          sync.Mutex
		completed   = make(map[int]bool)
		nodeResults = make(map[int][]utils.Finding)
		sem         = make(chan struct{}, d.Concurrency)
	)

	levels := d.topologicalLevels()

	for _, level := range levels {
		if ctx.Err() != nil {
			for _, node := range level {
				mu.Lock()
				done := completed[node.ID]
				mu.Unlock()
				if !done {
					if onProgress != nil {
						onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "skip"})
					}
					d.Graph.RecordSkip(node.ID)
				}
			}
			continue
		}

		var wg sync.WaitGroup
		for _, node := range level {
			if ctx.Err() != nil {
				if onProgress != nil {
					onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "skip"})
				}
				mu.Lock()
				completed[node.ID] = true
				mu.Unlock()
				d.Graph.RecordSkip(node.ID)
				continue
			}

			// Check dependencies
			depsMet := true
			for _, depID := range node.DependsOn {
				if !completed[depID] {
					depsMet = false
					break
				}
			}
			if !depsMet {
				if onProgress != nil {
					onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "skip"})
				}
				mu.Lock()
				completed[node.ID] = true
				mu.Unlock()
				d.Graph.RecordSkip(node.ID)
				continue
			}

			// Check fallback
			if node.FallbackFor > 0 {
				mu.Lock()
				parentFindings := nodeResults[node.FallbackFor]
				mu.Unlock()
				if len(parentFindings) > 0 {
					if onProgress != nil {
						onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "skip"})
					}
					mu.Lock()
					completed[node.ID] = true
					mu.Unlock()
					d.Graph.RecordSkip(node.ID)
					continue
				}
			}

			// Check condition
			if node.Condition != nil {
				var depFindings []utils.Finding
				mu.Lock()
				for _, depID := range node.DependsOn {
					depFindings = append(depFindings, nodeResults[depID]...)
				}
				mu.Unlock()
				if !node.Condition(depFindings) {
					if onProgress != nil {
						onProgress(NodeProgress{NodeID: node.ID, Name: node.Name, Phase: node.Phase, Status: "skip"})
					}
					mu.Lock()
					completed[node.ID] = true
					mu.Unlock()
					d.Graph.RecordSkip(node.ID)
					continue
				}
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(n *ChainNode) {
				defer wg.Done()
				defer func() { <-sem }()

				if onProgress != nil {
					onProgress(NodeProgress{NodeID: n.ID, Name: n.Name, Phase: n.Phase, Status: "running"})
				}

				start := time.Now()
				findings := n.Execute(target, cfg)
				elapsed := time.Since(start)

				mu.Lock()
				allFindings = append(allFindings, findings...)
				nodeResults[n.ID] = findings
				completed[n.ID] = true
				mu.Unlock()

				status := "done"
				if n.FallbackFor > 0 {
					d.Graph.RecordFallback(n, len(findings))
					status = "fallback"
				} else {
					d.Graph.RecordExecution(n, len(findings))
				}

				for _, f := range findings {
					if onFinding != nil {
						onFinding(f)
					}
				}

				if onProgress != nil {
					onProgress(NodeProgress{NodeID: n.ID, Name: n.Name, Phase: n.Phase, Status: status, Elapsed: elapsed})
				}
			}(node)
		}
		wg.Wait()
	}

	return allFindings
}
