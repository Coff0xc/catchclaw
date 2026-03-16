package chain

import (
	"fmt"
	"sync"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ChainNode represents a single attack step in the DAG
type ChainNode struct {
	ID        int
	Name      string
	Execute   func(target utils.Target, cfg ChainConfig) []utils.Finding
	DependsOn []int                          // node IDs this depends on
	Condition func([]utils.Finding) bool     // optional: only run if condition met
	Category  string                         // e.g. "auth", "injection", "recon"
	Severity  string                         // expected max severity
}

// DAGChain orchestrates attack chains using a directed acyclic graph
type DAGChain struct {
	Nodes       []*ChainNode
	Concurrency int
	Aggressive  bool
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
		nodeResults = make(map[int][]utils.Finding) // per-node results for conditions
		sem         = make(chan struct{}, d.Concurrency)
	)

	// Topological sort using Kahn's algorithm
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
				continue
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
					continue
				}
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(n *ChainNode) {
				defer wg.Done()
				defer func() { <-sem }()

				fmt.Printf("  [>] Running: %s (chain #%d)\n", n.Name, n.ID)
				findings := n.Execute(target, cfg)

				mu.Lock()
				allFindings = append(allFindings, findings...)
				nodeResults[n.ID] = findings
				completed[n.ID] = true
				mu.Unlock()

				if len(findings) > 0 {
					fmt.Printf("  [+] %s: %d findings\n", n.Name, len(findings))
				}
			}(node)
		}
		wg.Wait()
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[*] ═══ DAG chain complete: %d findings in %s ═══\n", len(allFindings), elapsed.Round(time.Millisecond))
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

	// Find all nodes with no dependencies
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
