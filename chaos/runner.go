package chaos

// Runner executes a list of experiments against a target URL.
type Runner struct {
	experiments []Experiment
	client      HTTPClient
}

// NewRunner creates a Runner with the given HTTP client and experiments.
func NewRunner(client HTTPClient, exps ...Experiment) *Runner {
	return &Runner{
		experiments: exps,
		client:      client,
	}
}

// Experiments returns the registered experiments (read-only view).
func (r *Runner) Experiments() []Experiment { return r.experiments }

// RunAll executes every registered experiment against target and returns all results.
func (r *Runner) RunAll(target string) []Result {
	results := make([]Result, 0, len(r.experiments))
	for _, exp := range r.experiments {
		results = append(results, exp.Run(target, r.client))
	}
	return results
}

// RunOne executes the named experiment and returns (result, true), or
// (zero, false) if no experiment with that name exists.
func (r *Runner) RunOne(target, name string) (Result, bool) {
	for _, exp := range r.experiments {
		if exp.Name() == name {
			return exp.Run(target, r.client), true
		}
	}
	return Result{}, false
}
