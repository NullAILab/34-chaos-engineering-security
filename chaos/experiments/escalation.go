package experiments

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// EscalationExperiment sends a non-admin bearer token to a privileged endpoint
// and expects the target to reject it with 403 Forbidden (or 401).
type EscalationExperiment struct {
	adminPath string
	token     string
}

// NewEscalation creates an EscalationExperiment.
// adminPath is appended to the base target URL (e.g. "/admin").
// token is the non-privileged bearer token to send.
func NewEscalation(adminPath, token string) *EscalationExperiment {
	if adminPath == "" {
		adminPath = "/admin"
	}
	if token == "" {
		token = "non-admin-chaos-test-token"
	}
	return &EscalationExperiment{adminPath: adminPath, token: token}
}

// Name implements chaos.Experiment.
func (e *EscalationExperiment) Name() string { return "permission-escalation" }

// Description implements chaos.Experiment.
func (e *EscalationExperiment) Description() string {
	return fmt.Sprintf(
		"Sends non-admin token to %s; expects 403 Forbidden",
		e.adminPath,
	)
}

// Run implements chaos.Experiment.
func (e *EscalationExperiment) Run(target string, client chaos.HTTPClient) chaos.Result {
	start := time.Now()
	url := target + e.adminPath

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return chaos.Result{
			ExperimentName: e.Name(),
			Target:         url,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("failed to build request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := client.Do(req)
	if err != nil {
		return chaos.Result{
			ExperimentName: e.Name(),
			Target:         url,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("request failed: %v", err),
			DurationMs:     time.Since(start).Milliseconds(),
		}
	}
	defer resp.Body.Close()

	outcome := chaos.OutcomeFail
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		outcome = chaos.OutcomePass
	}

	return chaos.Result{
		ExperimentName: e.Name(),
		Target:         url,
		Outcome:        outcome,
		ExpectedStatus: http.StatusForbidden,
		ActualStatus:   resp.StatusCode,
		Message:        fmt.Sprintf("non-admin token → %s → HTTP %d", e.adminPath, resp.StatusCode),
		DurationMs:     time.Since(start).Milliseconds(),
	}
}
