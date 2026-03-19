package tui

import (
	"github.com/coff0xc/lobster-guard/pkg/concurrent"
	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍ProgressMsg wraps engine progress updates.
type ProgressMsg concurrent.Progress

// ScanStartedMsg signals that a scan has begun.
type ScanStartedMsg struct {
	Total int
}

// ScanCompleteMsg signals scan completion.
type ScanCompleteMsg struct {
	Findings []utils.Finding
	Elapsed  string
}

// ScanErrorMsg signals a scan error.
type ScanErrorMsg struct {
	Err error
}

// LogLineMsg carries a single log line to the viewport.
type LogLineMsg string

// CmdResultMsg carries command execution feedback.
type CmdResultMsg struct {
	Output string
	IsErr  bool
}

// FindingMsg carries a single finding from the scan.
type FindingMsg utils.Finding

// NodeStatusMsg carries per-node status update.
type NodeStatusMsg struct {
	ID      int
	Name    string
	Status  string // "pending", "running", "done", "error", "skip"
	Elapsed string
}
