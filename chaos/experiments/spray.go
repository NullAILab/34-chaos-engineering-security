package experiments

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
)

// SprayConfig controls the credential-spray experiment.
type SprayConfig struct {
	// Attempts is the maximum number of login requests to send.
	Attempts int
	// Username is the account being sprayed.
	Username string
	// Password is the wrong password to use on every attempt.
	Password string
	// BodyFmt is a fmt.Sprintf template for the POST body (%s=username, %s=password).
	BodyFmt string
	// LockoutCodes are HTTP status codes that signal account lockout.
	// Defaults to [429, 423, 403] when empty.
	LockoutCodes []int
}

// SprayExperiment sends rapid failed login attempts and expects a lockout response.
type SprayExperiment struct {
	cfg SprayConfig
}

// NewSpray creates a SprayExperiment with the given config.
func NewSpray(cfg SprayConfig) *SprayExperiment {
	if len(cfg.LockoutCodes) == 0 {
		cfg.LockoutCodes = []int{429, 423, 403}
	}
	if cfg.BodyFmt == "" {
		cfg.BodyFmt = `{"username":%q,"password":%q}`
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 10
	}
	return &SprayExperiment{cfg: cfg}
}

// Name implements chaos.Experiment.
func (s *SprayExperiment) Name() string { return "credential-spray" }

// Description implements chaos.Experiment.
func (s *SprayExperiment) Description() string {
	return fmt.Sprintf(
		"Sends %d failed login attempts to %s; expects lockout (429/423/403)",
		s.cfg.Attempts, s.cfg.Username,
	)
}

// Run implements chaos.Experiment.
func (s *SprayExperiment) Run(target string, client chaos.HTTPClient) chaos.Result {
	start := time.Now()
	lockoutAt := -1
	lastStatus := 0

	for i := 0; i < s.cfg.Attempts; i++ {
		body := fmt.Sprintf(s.cfg.BodyFmt, s.cfg.Username, s.cfg.Password)
		req, err := http.NewRequest("POST", target, strings.NewReader(body))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		lastStatus = resp.StatusCode
		resp.Body.Close()

		if isLockoutCode(resp.StatusCode, s.cfg.LockoutCodes) {
			lockoutAt = i + 1
			break
		}
	}

	outcome := chaos.OutcomeFail
	msg := fmt.Sprintf("sent %d attempts, no lockout detected (last HTTP %d)", s.cfg.Attempts, lastStatus)
	if lockoutAt > 0 {
		outcome = chaos.OutcomePass
		msg = fmt.Sprintf("lockout triggered at attempt %d (HTTP %d)", lockoutAt, lastStatus)
	}

	return chaos.Result{
		ExperimentName: s.Name(),
		Target:         target,
		Outcome:        outcome,
		ExpectedStatus: 429,
		ActualStatus:   lastStatus,
		Message:        msg,
		DurationMs:     time.Since(start).Milliseconds(),
	}
}

func isLockoutCode(code int, lockoutCodes []int) bool {
	for _, c := range lockoutCodes {
		if code == c {
			return true
		}
	}
	return false
}
