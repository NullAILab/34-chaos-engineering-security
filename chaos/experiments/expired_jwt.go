// Package experiments contains individual chaos security experiments.
package experiments

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// ExpiredJWTExperiment sends a structurally valid but expired JWT token and
// expects the target to reject it with 401 Unauthorized.
type ExpiredJWTExperiment struct{}

// Name implements chaos.Experiment.
func (e *ExpiredJWTExperiment) Name() string { return "expired-jwt" }

// Description implements chaos.Experiment.
func (e *ExpiredJWTExperiment) Description() string {
	return "Sends an expired JWT token; expects 401 Unauthorized"
}

// Run implements chaos.Experiment.
func (e *ExpiredJWTExperiment) Run(target string, client chaos.HTTPClient) chaos.Result {
	start := time.Now()

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return chaos.Result{
			ExperimentName: e.Name(),
			Target:         target,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("failed to build request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+expiredJWT())

	resp, err := client.Do(req)
	if err != nil {
		return chaos.Result{
			ExperimentName: e.Name(),
			Target:         target,
			Outcome:        chaos.OutcomeError,
			Message:        fmt.Sprintf("request failed: %v", err),
			DurationMs:     time.Since(start).Milliseconds(),
		}
	}
	defer resp.Body.Close()

	outcome := chaos.OutcomeFail
	if resp.StatusCode == http.StatusUnauthorized {
		outcome = chaos.OutcomePass
	}

	return chaos.Result{
		ExperimentName: e.Name(),
		Target:         target,
		Outcome:        outcome,
		ExpectedStatus: http.StatusUnauthorized,
		ActualStatus:   resp.StatusCode,
		Message:        fmt.Sprintf("expired JWT → HTTP %d", resp.StatusCode),
		DurationMs:     time.Since(start).Milliseconds(),
	}
}

// expiredJWT returns a minimal unsigned JWT with exp=1000001 (year 1970, far in the past).
// header: {"alg":"none","typ":"JWT"}
// payload: {"sub":"chaos-test","iat":1000000,"exp":1000001}
func expiredJWT() string {
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	payload := "eyJzdWIiOiJjaGFvcy10ZXN0IiwiaWF0IjoxMDAwMDAwLCJleHAiOjEwMDAwMDF9"
	return header + "." + payload + "."
}
