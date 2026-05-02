// Binary: chaos-security
//
// Runs chaos engineering security experiments against a target URL and reports
// whether each security control (JWT validation, rate limiting, API key
// revocation, permission enforcement, account lockout) behaves correctly.
//
// [EDUCATIONAL — for testing your own staging/lab environments only]
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
	"github.com/NullAILab/34-chaos-engineering-security/chaos/experiments"
	"github.com/NullAILab/34-chaos-engineering-security/report"
)

func defaultExperiments() []chaos.Experiment {
	return []chaos.Experiment{
		&experiments.ExpiredJWTExperiment{},
		experiments.NewRevokedAPIKey(),
		experiments.NewRateLimit(20),
		experiments.NewEscalation("/admin", "non-admin-chaos-test-token"),
		experiments.NewSpray(experiments.SprayConfig{
			Attempts: 10,
			Username: "chaos-test@example.com",
			Password: "wrong-password-chaos",
		}),
	}
}

func main() {
	target := flag.String("target", "http://localhost:8080", "Target base URL")
	name := flag.String("experiment", "", "Run only this experiment (empty = all)")
	asJSON := flag.Bool("json", false, "Output JSON report")
	list := flag.Bool("list", false, "List available experiments and exit")
	flag.Parse()

	exps := defaultExperiments()

	if *list {
		fmt.Println("Available experiments:")
		for _, e := range exps {
			fmt.Printf("  %-30s %s\n", e.Name(), e.Description())
		}
		return
	}

	realClient := chaos.HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	})

	runner := chaos.NewRunner(realClient, exps...)

	var results []chaos.Result
	if *name != "" {
		res, ok := runner.RunOne(*target, *name)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown experiment %q — use -list to see available experiments\n", *name)
			os.Exit(1)
		}
		results = []chaos.Result{res}
	} else {
		results = runner.RunAll(*target)
	}

	r := report.New(*target, results)

	if *asJSON {
		out, err := r.ToJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(out)
	} else {
		fmt.Print(r.ToText())
	}

	if r.Summary.Fail > 0 || r.Summary.Errors > 0 {
		os.Exit(1)
	}
}
