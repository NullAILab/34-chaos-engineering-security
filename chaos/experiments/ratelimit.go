package experiments

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// RateLimitExperiment sends a rapid burst of requests and expects the target
// to enforce rate limiting with 429 Too Many Requests.
type RateLimitExperiment struct {
	burstSize int
}

// NewRateLimit creates a RateLimitExperiment.
// burstSize is the number of rapid requests to fire; defaults to 20.
func NewRateLimit(burstSize int) *RateLimitExperiment {
	if burstSize <= 0 {
		burstSize = 20
	}
	return &RateLimitExperiment{burstSize: burstSize}
}

// Name implements chaos.Experiment.
func (r *RateLimitExperiment) Name() string { return "rate-limit-breach" }

// Description implements chaos.Experiment.
func (r *RateLimitExperiment) Description() string {
	return fmt.Sprintf("Sends %d rapid requests; expects 429 Too Many Requests", r.burstSize)
}

// Run implements chaos.Experiment.
func (r *RateLimitExperiment) Run(target string, client chaos.HTTPClient) chaos.Result {
	start := time.Now()
	rateLimitedAt := -1
	lastStatus := 0

	for i := 0; i < r.burstSize; i++ {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			break
		}
		req.Header.Set("X-Chaos-Test", "rate-limit-breach")

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		lastStatus = resp.StatusCode
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitedAt = i + 1
			break
		}
	}

	outcome := chaos.OutcomeFail
	msg := fmt.Sprintf("sent %d requests, no rate limiting detected", r.burstSize)
	if rateLimitedAt > 0 {
		outcome = chaos.OutcomePass
		msg = fmt.Sprintf("rate limit triggered at request %d", rateLimitedAt)
	}

	return chaos.Result{
		ExperimentName: r.Name(),
		Target:         target,
		Outcome:        outcome,
		ExpectedStatus: http.StatusTooManyRequests,
		ActualStatus:   lastStatus,
		Message:        msg,
		DurationMs:     time.Since(start).Milliseconds(),
	}
}
