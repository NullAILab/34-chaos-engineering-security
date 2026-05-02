// Package report renders chaos experiment results as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// Summary holds aggregate counts for a report.
type Summary struct {
	Total  int `json:"total"`
	Pass   int `json:"pass"`
	Fail   int `json:"fail"`
	Errors int `json:"errors"`
}

// Report wraps experiment results with metadata.
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Target      string         `json:"target"`
	Results     []chaos.Result `json:"results"`
	Summary     Summary        `json:"summary"`
}

// New builds a Report from a slice of results.
func New(target string, results []chaos.Result) *Report {
	pass, fail, errs := chaos.Summary(results)
	return &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      target,
		Results:     results,
		Summary: Summary{
			Total:  len(results),
			Pass:   pass,
			Fail:   fail,
			Errors: errs,
		},
	}
}

// ToJSON renders the report as indented JSON.
func (r *Report) ToJSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ToText renders the report as a human-readable plain-text summary.
func (r *Report) ToText() string {
	const sep = "===================================================================="
	var sb strings.Builder

	sb.WriteString(sep + "\n")
	sb.WriteString("  CHAOS ENGINEERING SECURITY REPORT\n")
	sb.WriteString(fmt.Sprintf("  Target      : %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("  Generated   : %s\n", r.GeneratedAt))
	sb.WriteString(sep + "\n\n")

	for _, res := range r.Results {
		icon := "✓"
		if res.Outcome == chaos.OutcomeFail {
			icon = "✗"
		} else if res.Outcome == chaos.OutcomeError {
			icon = "!"
		}
		sb.WriteString(fmt.Sprintf(
			" %s [%-5s] %-28s  HTTP %3d (want %3d)  %dms\n",
			icon, res.Outcome, res.ExperimentName,
			res.ActualStatus, res.ExpectedStatus, res.DurationMs,
		))
		sb.WriteString(fmt.Sprintf("         %s\n\n", res.Message))
	}

	sb.WriteString(sep + "\n")
	sb.WriteString(fmt.Sprintf(
		"  PASS: %d  FAIL: %d  ERROR: %d  TOTAL: %d\n",
		r.Summary.Pass, r.Summary.Fail, r.Summary.Errors, r.Summary.Total,
	))
	verdict := "✓ All security controls verified"
	if r.Summary.Fail > 0 || r.Summary.Errors > 0 {
		verdict = "✗ Security gaps detected — review failed experiments"
	}
	sb.WriteString(fmt.Sprintf("  %s\n", verdict))
	sb.WriteString(sep + "\n")
	return sb.String()
}
