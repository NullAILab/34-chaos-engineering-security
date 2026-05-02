package chaos

// Outcome describes whether a chaos experiment passed or failed.
type Outcome string

const (
	// OutcomePass means the security control behaved as expected.
	OutcomePass Outcome = "PASS"
	// OutcomeFail means the security control did NOT respond as expected.
	OutcomeFail Outcome = "FAIL"
	// OutcomeError means the experiment could not run (network error, bad URL, etc.).
	OutcomeError Outcome = "ERROR"
)

// Result holds the outcome of a single experiment execution.
type Result struct {
	ExperimentName string  `json:"experiment"`
	Target         string  `json:"target"`
	Outcome        Outcome `json:"outcome"`
	ExpectedStatus int     `json:"expected_status"`
	ActualStatus   int     `json:"actual_status"`
	Message        string  `json:"message"`
	DurationMs     int64   `json:"duration_ms"`
}

// Experiment is implemented by every chaos security experiment.
type Experiment interface {
	Name() string
	Description() string
	Run(target string, client HTTPClient) Result
}

// Summary counts outcomes across a slice of results.
func Summary(results []Result) (pass, fail, errors int) {
	for _, r := range results {
		switch r.Outcome {
		case OutcomePass:
			pass++
		case OutcomeFail:
			fail++
		case OutcomeError:
			errors++
		}
	}
	return
}
