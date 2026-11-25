package report

import (
	"fmt"
	"strings"

	"github.com/Coff0xc/catchclaw/go/internal/core"
	"github.com/Coff0xc/catchclaw/go/internal/exploit"
)

func ChainTracesHTML(traces []*exploit.ChainTrace) string {
	if len(traces) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<h2>Attack Chain Visualization</h2>\n")

	complete := 0
	for _, t := range traces {
		if t.Complete {
			complete++
		}
	}
	fmt.Fprintf(&b, "<p>%d chains attempted, <span class=\"critical\">%d fully compromised</span></p>\n", len(traces), complete)

	b.WriteString(`<style>
.chain-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin:1rem 0}
.chain-card.complete{border-color:#f85149;box-shadow:0 0 12px rgba(248,81,73,.3)}
.chain-title{font-weight:bold;margin-bottom:.75rem;display:flex;justify-content:space-between;align-items:center}
.chain-badge{font-size:.75rem;padding:.15rem .6rem;border-radius:10px;background:#f85149;color:#fff}
.chain-badge.partial{background:#d29922}
.chain-flow{display:flex;align-items:stretch;flex-wrap:wrap;gap:0}
.stage-node{background:#0d1117;border:2px solid #30363d;border-radius:8px;padding:.6rem .8rem;min-width:140px;max-width:220px;flex-shrink:0}
.stage-node.hit{border-color:#3fb950}
.stage-node.miss{border-color:#f85149;opacity:.6}
.stage-num{font-size:.7rem;color:#8b949e}
.stage-name{font-size:.85rem;font-weight:600;margin:.2rem 0}
.stage-cve{font-size:.7rem;color:#db6d28}
.stage-acq{font-size:.7rem;color:#3fb950;margin-top:.3rem;word-break:break-all}
.stage-arrow{display:flex;align-items:center;padding:0 .4rem;color:#3fb950;font-size:1.3rem;flex-shrink:0}
.stage-arrow.broken{color:#f85149}
</style>`)

	for _, t := range traces {
		cls := "chain-card"
		badge := `<span class="chain-badge partial">PARTIAL</span>`
		if t.Complete {
			cls += " complete"
			badge = `<span class="chain-badge">FULL COMPROMISE</span>`
		}
		fmt.Fprintf(&b, `<div class="%s"><div class="chain-title"><span>%s</span>%s</div><div class="chain-flow">`,
			cls, htmlEscape(t.ChainName), badge)

		for i, st := range t.Stages {
			nodeCls := "stage-node miss"
			mark := "✗"
			if st.Hit {
				nodeCls = "stage-node hit"
				mark = "✓"
			}
			fmt.Fprintf(&b, `<div class="%s"><div class="stage-num">%s Stage %d</div><div class="stage-name">%s</div>`,
				nodeCls, mark, i+1, htmlEscape(st.Name))
			if st.CVE != "" {
				fmt.Fprintf(&b, `<div class="stage-cve">%s</div>`, htmlEscape(st.CVE))
			}
			if len(st.Acquired) > 0 {
				var acq []string
				for k, v := range st.Acquired {
					acq = append(acq, fmt.Sprintf("%s=%s", k, core.TruncateStr(v, 24)))
				}
				fmt.Fprintf(&b, `<div class="stage-acq">⚑ %s</div>`, htmlEscape(strings.Join(acq, " ")))
			}
			b.WriteString("</div>")

			if i < len(t.Stages)-1 {
				arrowCls := "stage-arrow"
				if !st.Hit {
					arrowCls += " broken"
				}
				fmt.Fprintf(&b, `<div class="%s">→</div>`, arrowCls)
			}
		}
		b.WriteString("</div></div>\n")
	}
	return b.String()
}

func ChainTracesMermaid(traces []*exploit.ChainTrace) string {
	if len(traces) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for ci, t := range traces {
		fmt.Fprintf(&b, "  subgraph chain%d[\"%s\"]\n", ci, sanitizeMermaid(t.ChainName))
		fmt.Fprintf(&b, "    direction LR\n")
		prevID := ""
		for i, st := range t.Stages {
			nodeID := fmt.Sprintf("c%d_s%d", ci, i)
			label := fmt.Sprintf("Stage %d: %s", i+1, st.Name)
			if st.CVE != "" {
				label += "<br/>" + st.CVE
			}
			fmt.Fprintf(&b, "    %s[\"%s\"]\n", nodeID, sanitizeMermaid(label))
			if st.Hit {
				fmt.Fprintf(&b, "    style %s fill:#1a7f37,color:#fff\n", nodeID)
			} else {
				fmt.Fprintf(&b, "    style %s fill:#cf222e,color:#fff\n", nodeID)
			}
			if prevID != "" {
				edge := "-->"
				if !t.Stages[i-1].Hit {
					edge = "-.->|broken|"
				} else if len(t.Stages[i-1].Acquired) > 0 {
					var keys []string
					for k := range t.Stages[i-1].Acquired {
						keys = append(keys, k)
					}
					edge = fmt.Sprintf("-->|%s|", sanitizeMermaid(strings.Join(keys, ",")))
				}
				fmt.Fprintf(&b, "    %s %s %s\n", prevID, edge, nodeID)
			}
			prevID = nodeID
		}
		b.WriteString("  end\n")
	}
	return b.String()
}

func ChainTracesMarkdown(traces []*exploit.ChainTrace) string {
	if len(traces) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Attack Chains\n\n")
	for _, t := range traces {
		status := "⚠️ PARTIAL"
		if t.Complete {
			status = "🔴 FULL COMPROMISE"
		}
		fmt.Fprintf(&b, "### %s — %s\n\n", t.ChainName, status)
		for i, st := range t.Stages {
			mark := "❌"
			if st.Hit {
				mark = "✅"
			}
			line := fmt.Sprintf("%s **Stage %d:** %s", mark, i+1, st.Name)
			if st.CVE != "" {
				line += " (" + st.CVE + ")"
			}
			if len(st.Acquired) > 0 {
				var acq []string
				for k, v := range st.Acquired {
					acq = append(acq, fmt.Sprintf("`%s=%s`", k, core.TruncateStr(v, 24)))
				}
				line += " → " + strings.Join(acq, " ")
			}
			b.WriteString(line + "\n\n")
		}
	}
	return b.String()
}

func sanitizeMermaid(s string) string {
	r := strings.NewReplacer("\"", "'", "[", "(", "]", ")", "{", "(", "}", ")", "\n", " ")
	return r.Replace(s)
}
