# Chaos Engineering Security Tool

![Go](https://img.shields.io/badge/Go-1.21%2B-blue?logo=go)
![Tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20%2B%20Responsible%20Use-blue)

Netflix popularised chaos engineering by randomly terminating production servers to prove their systems were resilient — but the same discipline applies to security controls. Do your APIs actually reject expired JWTs, or does the middleware silently pass them through after a config change? Does your rate limiter hold under a sudden burst of 20 requests? Has your API key revocation propagated within the SLA? This tool answers those questions by injecting five controlled security failure conditions at your staging endpoints and recording exactly which controls held and which failed — suitable as a CI/CD gate before every deployment.

## Features

- **5 security experiments** — expired JWT, revoked API key, rate-limit breach, privilege escalation, credential spray
- **Injectable HTTP client** — `HTTPClient` interface + `HTTPClientFunc` adapter; all 42 tests run offline with mock clients
- **PASS / FAIL / ERROR outcomes** — PASS means the control worked; FAIL means a security gap; ERROR means the target was unreachable
- **Text + JSON reports** — plain-text for humans, JSON for CI pipelines; exits 0 on all-pass, 1 on any failure
- **Runner** — `RunAll` or `RunOne` by name; duration tracked per experiment
- **Zero external dependencies** — pure Go stdlib

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.21+ |
| HTTP | stdlib `net/http` |
| CLI | stdlib `flag` |
| Testing | stdlib `testing` + `httptest` |

## Project Structure

```
34-chaos-engineering-security/
├── go.mod
├── main.go
├── chaos/
│   ├── client.go                    ← HTTPClient interface + HTTPClientFunc
│   ├── experiment.go                ← Experiment interface, Result, Outcome, Summary
│   ├── runner.go                    ← Runner (RunAll, RunOne)
│   └── experiments/
│       ├── expired_jwt.go           ← Sends expired JWT; expects 401
│       ├── revoked_api_key.go       ← Sends revoked X-API-Key; expects 401/403
│       ├── ratelimit.go             ← Sends burst of N requests; expects 429
│       ├── escalation.go            ← Sends non-admin token to /admin; expects 403
│       └── spray.go                 ← Credential spray; expects lockout (429/423/403)
├── report/
│   └── report.go                    ← Text + JSON report rendering
├── chaos_test.go                    ← 42 offline tests
├── LICENSE
└── README.md
```

## Usage

```bash
go build -o chaos-security .

# List available experiments
./chaos-security -list

# Run all experiments against a staging target
./chaos-security -target http://api.staging.example.com

# Run one experiment
./chaos-security -target http://api.staging.example.com -experiment expired-jwt

# JSON output (pipe to CI tools)
./chaos-security -target http://api.staging.example.com -json
```

**Example output:**

```
====================================================================
  CHAOS ENGINEERING SECURITY REPORT
  Target    : http://api.staging.example.com
====================================================================

 ✓ [PASS ] expired-jwt            HTTP 401 (want 401)   12ms
 ✓ [PASS ] revoked-api-key        HTTP 401 (want 401)    8ms
 ✗ [FAIL ] rate-limit-breach      HTTP 200 (want 429)   95ms
           sent 20 requests, no rate limiting detected
 ✓ [PASS ] permission-escalation  HTTP 403 (want 403)    6ms
 ✓ [PASS ] credential-spray       HTTP 429 (want 429)   44ms

====================================================================
  PASS: 4  FAIL: 1  ERROR: 0
  ✗ Security gaps detected — review failed experiments
====================================================================
```

**Exit codes:**

| Code | Meaning                  |
|------|--------------------------|
| 0    | All experiments passed   |
| 1    | One or more failures     |

## Running Tests

```bash
go test ./... -v
```

All 42 tests run offline using mock HTTP clients — no staging server required.

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Principles of Chaos Engineering](https://principlesofchaos.org/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## License

MIT License + Responsible Use Guidelines. See [LICENSE](LICENSE) for full terms.
