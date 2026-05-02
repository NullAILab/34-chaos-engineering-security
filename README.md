# 34 — Chaos Engineering Security Tool

> **Difficulty:** Intermediate | **Time:** 3–5 days | **Language:** Go

Tests security resilience by injecting controlled failure conditions at your own
staging endpoints — expired JWTs, revoked API keys, credential spray, rate limit
breach, and privilege escalation attempts — then reports which controls held.

---

## What It Does

| Experiment            | What It Tests                        | Expected Result          |
|-----------------------|--------------------------------------|--------------------------|
| `expired-jwt`         | JWT expiry enforcement               | 401 Unauthorized         |
| `revoked-api-key`     | Key revocation propagation           | 401 or 403               |
| `rate-limit-breach`   | Rate limiter under burst traffic     | 429 Too Many Requests    |
| `permission-escalation` | AuthZ on privileged endpoints      | 403 Forbidden            |
| `credential-spray`    | Account lockout after N bad attempts | 429 / 423 / 403 lockout  |

Each experiment uses an injectable `HTTPClient` interface, so all 42 tests run
completely offline with mock HTTP clients.

---

## Tech Stack

| Component      | Technology          |
|----------------|---------------------|
| Language       | Go 1.21+            |
| HTTP client    | stdlib `net/http`   |
| CLI            | stdlib `flag`       |
| Output         | JSON + plain text   |
| Tests          | stdlib `testing`    |

Zero external dependencies.

---

## Project Structure

```
34-chaos-engineering-security/
├── go.mod
├── main.go                          ← CLI entry point
├── chaos/
│   ├── client.go                    ← HTTPClient interface + HTTPClientFunc
│   ├── experiment.go                ← Experiment interface, Result, Outcome, Summary
│   ├── runner.go                    ← Runner (RunAll, RunOne)
│   └── experiments/
│       ├── expired_jwt.go           ← Expired JWT experiment
│       ├── spray.go                 ← Credential spray experiment
│       ├── ratelimit.go             ← Rate-limit breach experiment
│       ├── apikey.go                ← Revoked API key experiment
│       └── escalation.go           ← Permission escalation experiment
├── report/
│   └── report.go                    ← Text + JSON report rendering
├── chaos_test.go                    ← 42 offline tests
├── LICENSE
└── README.md
```

---

## Usage

```bash
# Build
go build -o chaos-security .

# List available experiments
./chaos-security -list

# Run all experiments against a staging target
./chaos-security -target http://api.staging.example.com

# Run a single experiment
./chaos-security -target http://api.staging.example.com -experiment expired-jwt

# JSON output (useful for CI/CD gates)
./chaos-security -target http://api.staging.example.com -json
```

**Example output:**

```
====================================================================
  CHAOS ENGINEERING SECURITY REPORT
  Target      : http://api.staging.example.com
  Generated   : 2026-05-02T03:30:00Z
====================================================================

 ✓ [PASS ] expired-jwt               HTTP 401 (want 401)  12ms
         expired JWT → HTTP 401

 ✓ [PASS ] revoked-api-key           HTTP 401 (want 401)   8ms
         revoked API key → HTTP 401

 ✗ [FAIL ] rate-limit-breach         HTTP 200 (want 429)  95ms
         sent 20 requests, no rate limiting detected

 ✓ [PASS ] permission-escalation     HTTP 403 (want 403)   6ms
         non-admin token → /admin → HTTP 403

 ✓ [PASS ] credential-spray          HTTP 429 (want 429)  44ms
         lockout triggered at attempt 5

====================================================================
  PASS: 4  FAIL: 1  ERROR: 0  TOTAL: 5
  ✗ Security gaps detected — review failed experiments
====================================================================
```

**Exit codes:**

| Code | Meaning                          |
|------|----------------------------------|
| 0    | All experiments passed           |
| 1    | One or more failures / errors    |

---

## Running Tests

```bash
go test ./... -v
```

All 42 tests run offline — no real HTTP server needed.

---

## Learning Objectives

- Chaos engineering principles: steady-state hypothesis and game days
- Security resilience testing methodology
- JWT validation: what happens when you send an expired token?
- Credential stuffing vs. spraying — and why lockout policies matter
- Rate limiting under burst traffic
- Privilege escalation and authorization enforcement

---

*NullAI Lab — Project 34 | Chaos Engineering Security Tool*
