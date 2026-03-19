// Concurrent operation for finding flaws — optimized x-platform checks
#[allow(dead_code)]
use crate::config::AppConfig;
use crate::utils::{Finding, Severity, Target};
use colored::Colorize;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

// ---------------------------------------------------------------------------
// Node status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Pending,
    Running,
    Done,
    Skipped,
    Fallback,
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Done => write!(f, "done"),
            Self::Skipped => write!(f, "skip"),
            Self::Fallback => write!(f, "fallback"),
        }
    }
}

// ---------------------------------------------------------------------------
// AttackEdge / AttackGraph
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackEdge {
    pub from_id: u32,
    pub to_id: u32,
    pub to_name: String,
    pub findings: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AttackGraph {
    pub edges: Vec<AttackEdge>,
    pub node_status: HashMap<u32, String>,
    pub node_findings: HashMap<u32, usize>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_execution(&mut self, id: u32, name: &str, deps: &[u32], findings: usize) {
        self.node_status.insert(id, "executed".into());
        self.node_findings.insert(id, findings);
        for &dep in deps {
            self.edges.push(AttackEdge {
                from_id: dep,
                to_id: id,
                to_name: name.into(),
                findings: self.node_findings.get(&dep).copied().unwrap_or(0),
            });
        }
    }

    pub fn record_skip(&mut self, id: u32) {
        self.node_status.insert(id, "skipped".into());
    }

    pub fn record_fallback(&mut self, id: u32, name: &str, deps: &[u32], findings: usize) {
        self.node_status.insert(id, "fallback".into());
        self.node_findings.insert(id, findings);
        for &dep in deps {
            self.edges.push(AttackEdge {
                from_id: dep,
                to_id: id,
                to_name: name.into(),
                findings: self.node_findings.get(&dep).copied().unwrap_or(0),
            });
        }
    }

    pub fn to_mermaid(&self, nodes: &HashMap<u32, (String, String)>) -> String {
        let mut sb = String::from("graph TD\n");
        for (&id, status) in &self.node_status {
            let (name, phase) = nodes
                .get(&id)
                .cloned()
                .unwrap_or_else(|| (format!("Node{id}"), "?".into()));
            let findings = self.node_findings.get(&id).copied().unwrap_or(0);
            let label = format!("{name}\n[{phase}] {findings} findings");
            let class = match (status.as_str(), findings > 0) {
                ("executed", true) => "hit",
                ("executed", false) => "clean",
                ("fallback", true) => "fallback_hit",
                ("fallback", false) => "fallback",
                _ => "skip",
            };
            sb.push_str(&format!("    N{id}[\"{label}\"]:::{class}\n"));
        }
        for e in &self.edges {
            sb.push_str(&format!("    N{} --> N{}\n", e.from_id, e.to_id));
        }
        sb.push_str("    classDef hit fill:#ff6b6b,stroke:#c92a2a,color:#fff\n");
        sb.push_str("    classDef clean fill:#51cf66,stroke:#2b8a3e,color:#fff\n");
        sb.push_str("    classDef skip fill:#adb5bd,stroke:#868e96,color:#fff\n");
        sb.push_str("    classDef fallback fill:#ffd43b,stroke:#f08c00,color:#000\n");
        sb.push_str("    classDef fallback_hit fill:#ff922b,stroke:#e8590c,color:#fff\n");
        sb
    }
}

// ---------------------------------------------------------------------------
// ChainNode
// ---------------------------------------------------------------------------

pub type ExecFn = Box<
    dyn Fn(Target, AppConfig) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send>> + Send + Sync,
>;

pub type ConditionFn = Box<dyn Fn(&HashMap<u32, Vec<Finding>>) -> bool + Send + Sync>;

pub struct ChainNode {
    pub id: u32,
    pub name: String,
    pub category: String,
    pub phase: String,
    pub depends_on: Vec<u32>,
    pub fallback_for: Option<u32>,
    pub execute: ExecFn,
    pub condition: Option<ConditionFn>,
}

// ---------------------------------------------------------------------------
// DagChain
// ---------------------------------------------------------------------------

pub type ProgressFn = Box<dyn Fn(u32, &str, NodeStatus) + Send + Sync>;

pub struct DagChain {
    nodes: Vec<ChainNode>,
    node_map: HashMap<u32, usize>,
    concurrency: usize,
}

impl DagChain {
    pub fn new(concurrency: usize) -> Self {
        Self {
            nodes: Vec::new(),
            node_map: HashMap::new(),
            concurrency: concurrency.max(1),
        }
    }

    pub fn add_node(&mut self, node: ChainNode) {
        let idx = self.nodes.len();
        self.node_map.insert(node.id, idx);
        self.nodes.push(node);
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Compute risk score 0-100 from findings.
    pub fn chain_score(findings: &[Finding]) -> u32 {
        let raw: u32 = findings.iter().map(|f| f.severity.score()).sum();
        raw.min(100)
    }

    /// Topological sort via Kahn's algorithm — returns levels of node indices.
    fn topological_levels(&self) -> Vec<Vec<usize>> {
        let mut in_degree: HashMap<u32, usize> = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();

        for node in &self.nodes {
            in_degree.entry(node.id).or_insert(0);
            for &dep in &node.depends_on {
                children.entry(dep).or_default().push(node.id);
                *in_degree.entry(node.id).or_insert(0) += 1;
            }
        }

        let mut levels = Vec::new();
        let mut queue: Vec<u32> = self
            .nodes
            .iter()
            .filter(|n| in_degree.get(&n.id).copied().unwrap_or(0) == 0)
            .map(|n| n.id)
            .collect();

        while !queue.is_empty() {
            let mut level_indices = Vec::new();
            let mut next_queue = Vec::new();

            for id in &queue {
                if let Some(&idx) = self.node_map.get(id) {
                    level_indices.push(idx);
                }
                if let Some(kids) = children.get(id) {
                    for &kid in kids {
                        let deg = in_degree.get_mut(&kid).unwrap();
                        *deg -= 1;
                        if *deg == 0 {
                            next_queue.push(kid);
                        }
                    }
                }
            }

            levels.push(level_indices);
            queue = next_queue;
        }

        levels
    }

    /// Execute the full DAG with topological ordering and bounded concurrency.
    pub async fn execute(
        self,
        target: Target,
        cfg: AppConfig,
        on_progress: Option<ProgressFn>,
    ) -> (Vec<Finding>, AttackGraph) {
        if self.nodes.is_empty() {
            return (Vec::new(), AttackGraph::new());
        }

        println!(
            "\n{} DAG Attack Chain ({} nodes, concurrency={}) {}",
            "[*]".cyan(),
            self.nodes.len(),
            self.concurrency,
            "═".repeat(30)
        );
        println!("{} Target: {}", "[*]".cyan(), target);

        let start = std::time::Instant::now();
        let levels = self.topological_levels();

        // Move nodes into Arc-indexed storage
        let nodes: Vec<Arc<ChainNode>> = self.nodes.into_iter().map(Arc::new).collect();
        let _node_by_id: HashMap<u32, Arc<ChainNode>> = nodes
            .iter()
            .map(|n| (n.id, Arc::clone(n)))
            .collect();

        let graph = Arc::new(Mutex::new(AttackGraph::new()));
        let all_findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));
        let completed: Arc<Mutex<HashMap<u32, bool>>> = Arc::new(Mutex::new(HashMap::new()));
        let node_results: Arc<Mutex<HashMap<u32, Vec<Finding>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let on_progress = on_progress.map(Arc::new);

        for (level_idx, level) in levels.iter().enumerate() {
            if level.is_empty() {
                continue;
            }
            println!(
                "\n{} --- Level {}: {} nodes ---",
                "[*]".cyan(),
                level_idx,
                level.len()
            );

            let mut join_set = tokio::task::JoinSet::new();

            for &idx in level {
                let node = Arc::clone(&nodes[idx]);

                // Check dependencies met
                let deps_met = {
                    let comp = completed.lock().await;
                    node.depends_on.iter().all(|d| comp.get(d).copied().unwrap_or(false))
                };
                if !deps_met {
                    println!("  {} Skipping {} (unmet dependencies)", "[!]".yellow(), node.name);
                    graph.lock().await.record_skip(node.id);
                    continue;
                }

                // Check fallback: skip if parent succeeded
                if let Some(parent_id) = node.fallback_for {
                    let parent_ok = {
                        let nr = node_results.lock().await;
                        nr.get(&parent_id).map_or(false, |f| !f.is_empty())
                    };
                    if parent_ok {
                        println!(
                            "  {} Skipping fallback {} (parent #{} succeeded)",
                            "[~]".dimmed(),
                            node.name,
                            parent_id
                        );
                        completed.lock().await.insert(node.id, true);
                        graph.lock().await.record_skip(node.id);
                        continue;
                    }
                }

                // Check condition
                if let Some(ref cond) = node.condition {
                    let nr = node_results.lock().await;
                    if !cond(&nr) {
                        println!("  {} Skipping {} (condition not met)", "[~]".dimmed(), node.name);
                        completed.lock().await.insert(node.id, true);
                        graph.lock().await.record_skip(node.id);
                        continue;
                    }
                }

                // Spawn task
                let permit = Arc::clone(&sem);
                let target = target.clone();
                let cfg = cfg.clone();
                let all_f = Arc::clone(&all_findings);
                let comp = Arc::clone(&completed);
                let nr = Arc::clone(&node_results);
                let g = Arc::clone(&graph);
                let prog = on_progress.clone();

                join_set.spawn(async move {
                    let _permit = permit.acquire().await.unwrap();

                    let phase = if node.phase.is_empty() { "?" } else { &node.phase };
                    println!("  {} Running: {} (chain #{}) [{}]", "[>]".green(), node.name, node.id, phase);

                    if let Some(ref p) = prog {
                        p(node.id, &node.name, NodeStatus::Running);
                    }

                    let findings = (node.execute)(target, cfg).await;
                    let count = findings.len();

                    {
                        let mut af = all_f.lock().await;
                        af.extend(findings.clone());
                    }
                    {
                        let mut nres = nr.lock().await;
                        nres.insert(node.id, findings);
                    }
                    {
                        let mut c = comp.lock().await;
                        c.insert(node.id, true);
                    }

                    let status = if node.fallback_for.is_some() {
                        let mut gg = g.lock().await;
                        gg.record_fallback(node.id, &node.name, &node.depends_on, count);
                        NodeStatus::Fallback
                    } else {
                        let mut gg = g.lock().await;
                        gg.record_execution(node.id, &node.name, &node.depends_on, count);
                        NodeStatus::Done
                    };

                    if count > 0 {
                        println!("  {} {}: {} findings", "[+]".green(), node.name, count);
                    }

                    if let Some(ref p) = prog {
                        p(node.id, &node.name, status);
                    }
                });
            }

            // Wait for all tasks in this level
            while join_set.join_next().await.is_some() {}
        }

        let elapsed = start.elapsed();
        let findings = match Arc::try_unwrap(all_findings) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => arc.lock().await.clone(),
        };
        let score = Self::chain_score(&findings);

        println!(
            "\n{} DAG chain complete: {} findings, risk score {}/100, {:?} {}",
            "[*]".cyan(),
            findings.len(),
            score,
            elapsed,
            "═".repeat(20)
        );

        let attack_graph = match Arc::try_unwrap(graph) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => arc.lock().await.clone(),
        };

        (findings, attack_graph)
    }

    /// Execute a single node by ID.
    pub async fn execute_single(self, id: u32, target: Target, cfg: AppConfig) -> Vec<Finding> {
        let node = match self.nodes.into_iter().find(|n| n.id == id) {
            Some(n) => n,
            None => {
                println!("  {} Chain #{} not found", "[-]".red(), id);
                return Vec::new();
            }
        };
        println!(
            "{} Running single chain: {} (#{})",
            "[*]".cyan(),
            node.name,
            node.id
        );
        (node.execute)(target, cfg).await
    }

    /// Execute only nodes matching given ATT&CK phases.
    pub async fn execute_phase(
        self,
        target: Target,
        cfg: AppConfig,
        phases: &[&str],
        on_progress: Option<ProgressFn>,
    ) -> (Vec<Finding>, AttackGraph) {
        let phase_set: std::collections::HashSet<&str> = phases.iter().copied().collect();
        let mut filtered = DagChain::new(self.concurrency);
        for node in self.nodes {
            if phase_set.contains(node.phase.as_str()) {
                filtered.add_node(node);
            }
        }
        filtered.execute(target, cfg, on_progress).await
    }

    /// Execute only nodes matching given categories.
    pub async fn execute_category(
        self,
        target: Target,
        cfg: AppConfig,
        categories: &[&str],
        on_progress: Option<ProgressFn>,
    ) -> (Vec<Finding>, AttackGraph) {
        let cat_set: std::collections::HashSet<&str> = categories.iter().copied().collect();
        let mut filtered = DagChain::new(self.concurrency);
        for node in self.nodes {
            if cat_set.contains(node.category.as_str()) {
                filtered.add_node(node);
            }
        }
        filtered.execute(target, cfg, on_progress).await
    }
}

// ---------------------------------------------------------------------------
// Condition helpers
// ---------------------------------------------------------------------------

/// Returns true if any dependency produced findings.
pub fn has_any_finding(results: &HashMap<u32, Vec<Finding>>) -> bool {
    results.values().any(|f| !f.is_empty())
}

/// Returns true if any dependency produced CRITICAL or HIGH findings.
pub fn has_critical_or_high(results: &HashMap<u32, Vec<Finding>>) -> bool {
    results.values().any(|findings| {
        findings
            .iter()
            .any(|f| f.severity >= Severity::High)
    })
}

/// Returns true if a specific node produced findings.
pub fn node_has_findings(results: &HashMap<u32, Vec<Finding>>, node_id: u32) -> bool {
    results.get(&node_id).map_or(false, |f| !f.is_empty())
}
