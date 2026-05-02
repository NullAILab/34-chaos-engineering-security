package experiments

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// RevokedAPIKeyExperiment sends a revoked (or obviously invalid) API key
// and expects the target to reject it with 401 or 403.
type RevokedAPIKeyExperiment struct {
	headerName string
	revokedKey string
}

// NewRevokedAPIKey creates a RevokedAPIKeyExperiment with sensible defaults.
func NewRevokedAPIKey() *RevokedAPIKeyExperiment {
	return &RevokedAPIKeyExperiment{
		headerName: "X-API-Key",
		revokedKey: "revoked-chaos-test-key-00000000",
	}
}

// NewRevokedAPIKeyCustom creates a RevokedAPIKeyExperiment with a custom header and key.
func NewRevokedAPIKeyCustom(header, key string) *RevokedAPIKeyExperiment {
	return &RevokedAPIKeyExperiment{headerName: header, revokedKey: key}
}

// Name implements chaos.Experiment.
func (a *RevokedAPIKeyExperiment) Name() string { return "revoked-api-key" }

// Description implements chaos.Experiment.
func (a *RevokedAPIKeyExperiment) Description() string {
	return fmt.Sprintf("Sends revoked key via %s header; expects 401 or 403", a.headerName)
}

// Run implements chaos.Experiment.
func (a *RevokedAPIKeyExperiment) Run(target string, client chaos.HTTPClient) chaos.Result {
	start := time.Now()

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return chaos.Result{
			ExperimentName: a.Name(),
			Target:         target,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("failed to build request: %v", err),
		}
	}
	req.Header.Set(a.headerName, a.revokedKey)

	resp, err := client.Do(req)
	if err != nil {
		return chaos.Result{
			ExperimentName: a.Name(),
			Target:         target,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("request failed: %v", err),
			DurationMs:     time.Since(start).Milliseconds(),
		}
	}
	defer resp.Body.Close()

	outcome := chaos.OutcomeFail
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		outcome = chaos.OutcomePass
	}

	return chaos.Result{
		ExperimentName: a.Name(),
		Target:         target,
		Outcome:        outcome,
		ExpectedStatus: http.StatusUnauthorized,
		ActualStatus:   resp.StatusCode,
		Message:        fmt.Sprintf("revoked API key → HTTP %d", resp.StatusCode),
		DurationMs:     time.Since(start).Milliseconds(),
	}
}
