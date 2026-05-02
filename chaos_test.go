package main_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NullAILab/34-chaos-engineering-security/chaos"
	"github.com/NullAILab/34-chaos-engineering-security/chaos/experiments"
	"github.com/NullAILab/34-chaos-engineering-security/report"
)

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

// mockStatus returns a client that always responds with the given HTTP status.
func mockStatus(status int) chaos.HTTPClient {
	return chaos.HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
}

// mockSequence returns a client that cycles through statuses in order,
// staying on the last value once the slice is exhausted.
func mockSequence(statuses []int) chaos.HTTPClient {
	var idx atomic.Int64
	return chaos.HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		i := int(idx.Load())
		if i < len(statuses)-1 {
			idx.Add(1)
		}
		return &http.Response{
			StatusCode: statuses[i],
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
}

// mockError returns a client that always returns a network error.
func mockError() chaos.HTTPClient {
	return chaos.HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})
}

// ---------------------------------------------------------------------------
// HTTPClientFunc
// ---------------------------------------------------------------------------

func TestHTTPClientFunc_ImplementsInterface(t *testing.T) {
	var _ chaos.HTTPClient = chaos.HTTPClientFunc(nil)
}

// ---------------------------------------------------------------------------
// Outcome constants
// ---------------------------------------------------------------------------

func TestOutcomeValues(t *testing.T) {
	if chaos.OutcomePass == chaos.OutcomeFail {
		t.Error("PASS and FAIL must be distinct")
	}
	if chaos.OutcomePass == chaos.OutcomeError {
		t.Error("PASS and ERROR must be distinct")
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

func TestSummary_Empty(t *testing.T) {
	p, f, e := chaos.Summary(nil)
	if p != 0 || f != 0 || e != 0 {
		t.Errorf("empty summary want 0/0/0 got %d/%d/%d", p, f, e)
	}
}

func TestSummary_Counts(t *testing.T) {
	results := []chaos.Result{
		{Outcome: chaos.OutcomePass},
		{Outcome: chaos.OutcomePass},
		{Outcome: chaos.OutcomeFail},
		{Outcome: chaos.OutcomeError},
	}
	p, f, e := chaos.Summary(results)
	if p != 2 || f != 1 || e != 1 {
		t.Errorf("want 2/1/1 got %d/%d/%d", p, f, e)
	}
}

// ---------------------------------------------------------------------------
// ExpiredJWT experiment
// ---------------------------------------------------------------------------

func TestExpiredJWT_Pass_On401(t *testing.T) {
	exp := &experiments.ExpiredJWTExperiment{}
	result := exp.Run("http://example.com", mockStatus(401))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS, got %s: %s", result.Outcome, result.Message)
	}
	if result.ActualStatus != 401 {
		t.Errorf("want ActualStatus 401, got %d", result.ActualStatus)
	}
	if result.ExpectedStatus != 401 {
		t.Errorf("want ExpectedStatus 401, got %d", result.ExpectedStatus)
	}
}

func TestExpiredJWT_Fail_On200(t *testing.T) {
	exp := &experiments.ExpiredJWTExperiment{}
	result := exp.Run("http://example.com", mockStatus(200))
	if result.Outcome != chaos.OutcomeFail {
		t.Errorf("want FAIL, got %s", result.Outcome)
	}
}

func TestExpiredJWT_Error_OnNetworkFailure(t *testing.T) {
	exp := &experiments.ExpiredJWTExperiment{}
	result := exp.Run("http://example.com", mockError())
	if result.Outcome != chaos.OutcomeError {
		t.Errorf("want ERROR, got %s", result.Outcome)
	}
}

func TestExpiredJWT_Error_OnBadURL(t *testing.T) {
	exp := &experiments.ExpiredJWTExperiment{}
	result := exp.Run("://bad-url", mockStatus(200))
	if result.Outcome != chaos.OutcomeError {
		t.Errorf("want ERROR on bad URL, got %s", result.Outcome)
	}
}

func TestExpiredJWT_Name(t *testing.T) {
	exp := &experiments.ExpiredJWTExperiment{}
	if exp.Name() != "expired-jwt" {
		t.Errorf("unexpected name: %s", exp.Name())
	}
}

// ---------------------------------------------------------------------------
// CredentialSpray experiment
// ---------------------------------------------------------------------------

func TestSpray_Pass_WhenLockoutTriggered(t *testing.T) {
	// First 4 attempts return 200, 5th returns 429 → lockout
	client := mockSequence([]int{200, 200, 200, 200, 429})
	exp := experiments.NewSpray(experiments.SprayConfig{
		Attempts: 10,
		Username: "user@example.com",
		Password: "wrong",
	})
	result := exp.Run("http://example.com/login", client)
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS when lockout triggered, got %s: %s", result.Outcome, result.Message)
	}
	if !strings.Contains(result.Message, "lockout triggered at attempt 5") {
		t.Errorf("want 'lockout triggered at attempt 5' in message, got: %s", result.Message)
	}
}

func TestSpray_Fail_WhenNoLockout(t *testing.T) {
	// All 5 attempts return 200 — no lockout
	exp := experiments.NewSpray(experiments.SprayConfig{
		Attempts: 5,
		Username: "user@example.com",
		Password: "wrong",
	})
	result := exp.Run("http://example.com/login", mockStatus(200))
	if result.Outcome != chaos.OutcomeFail {
		t.Errorf("want FAIL when no lockout, got %s", result.Outcome)
	}
}

func TestSpray_Pass_On423Lockout(t *testing.T) {
	// 423 Locked is also a valid lockout code
	client := mockSequence([]int{200, 200, 423})
	exp := experiments.NewSpray(experiments.SprayConfig{
		Attempts: 10,
		Username: "user@example.com",
		Password: "wrong",
	})
	result := exp.Run("http://example.com/login", client)
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 423, got %s", result.Outcome)
	}
}

func TestSpray_Pass_On403Lockout(t *testing.T) {
	client := mockSequence([]int{200, 403})
	exp := experiments.NewSpray(experiments.SprayConfig{
		Attempts: 10,
		Username: "user@example.com",
		Password: "wrong",
	})
	result := exp.Run("http://example.com/login", client)
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 403, got %s", result.Outcome)
	}
}

func TestSpray_DefaultsApplied(t *testing.T) {
	exp := experiments.NewSpray(experiments.SprayConfig{})
	if exp.Name() != "credential-spray" {
		t.Errorf("unexpected name: %s", exp.Name())
	}
}

// ---------------------------------------------------------------------------
// RateLimit experiment
// ---------------------------------------------------------------------------

func TestRateLimit_Pass_WhenThrottled(t *testing.T) {
	// First 9 succeed, 10th is throttled
	statuses := make([]int, 10)
	for i := range statuses {
		statuses[i] = 200
	}
	statuses[9] = 429
	exp := experiments.NewRateLimit(20)
	result := exp.Run("http://example.com/api", mockSequence(statuses))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS when throttled, got %s: %s", result.Outcome, result.Message)
	}
	if !strings.Contains(result.Message, "rate limit triggered at request 10") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestRateLimit_Fail_WhenNeverThrottled(t *testing.T) {
	exp := experiments.NewRateLimit(5)
	result := exp.Run("http://example.com/api", mockStatus(200))
	if result.Outcome != chaos.OutcomeFail {
		t.Errorf("want FAIL when never throttled, got %s", result.Outcome)
	}
}

func TestRateLimit_DefaultBurstSize(t *testing.T) {
	exp := experiments.NewRateLimit(0)
	if exp.Name() != "rate-limit-breach" {
		t.Errorf("unexpected name: %s", exp.Name())
	}
}

func TestRateLimit_ImmediateThrottle(t *testing.T) {
	// 429 on the very first request
	exp := experiments.NewRateLimit(5)
	result := exp.Run("http://example.com/api", mockStatus(429))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on immediate throttle, got %s", result.Outcome)
	}
	if !strings.Contains(result.Message, "request 1") {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// RevokedAPIKey experiment
// ---------------------------------------------------------------------------

func TestRevokedAPIKey_Pass_On401(t *testing.T) {
	exp := experiments.NewRevokedAPIKey()
	result := exp.Run("http://example.com/api", mockStatus(401))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 401, got %s", result.Outcome)
	}
}

func TestRevokedAPIKey_Pass_On403(t *testing.T) {
	exp := experiments.NewRevokedAPIKey()
	result := exp.Run("http://example.com/api", mockStatus(403))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 403, got %s", result.Outcome)
	}
}

func TestRevokedAPIKey_Fail_On200(t *testing.T) {
	exp := experiments.NewRevokedAPIKey()
	result := exp.Run("http://example.com/api", mockStatus(200))
	if result.Outcome != chaos.OutcomeFail {
		t.Errorf("want FAIL on 200, got %s", result.Outcome)
	}
}

func TestRevokedAPIKey_Error_OnNetworkFailure(t *testing.T) {
	exp := experiments.NewRevokedAPIKey()
	result := exp.Run("http://example.com/api", mockError())
	if result.Outcome != chaos.OutcomeError {
		t.Errorf("want ERROR on network failure, got %s", result.Outcome)
	}
}

func TestRevokedAPIKey_CustomHeader(t *testing.T) {
	exp := experiments.NewRevokedAPIKeyCustom("Authorization", "Bearer bad-key")
	if exp.Name() != "revoked-api-key" {
		t.Errorf("unexpected name: %s", exp.Name())
	}
}

// ---------------------------------------------------------------------------
// Escalation experiment
// ---------------------------------------------------------------------------

func TestEscalation_Pass_On403(t *testing.T) {
	exp := experiments.NewEscalation("/admin", "user-token")
	result := exp.Run("http://example.com", mockStatus(403))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 403, got %s", result.Outcome)
	}
}

func TestEscalation_Pass_On401(t *testing.T) {
	exp := experiments.NewEscalation("/admin", "user-token")
	result := exp.Run("http://example.com", mockStatus(401))
	if result.Outcome != chaos.OutcomePass {
		t.Errorf("want PASS on 401, got %s", result.Outcome)
	}
}

func TestEscalation_Fail_On200(t *testing.T) {
	exp := experiments.NewEscalation("/admin", "user-token")
	result := exp.Run("http://example.com", mockStatus(200))
	if result.Outcome != chaos.OutcomeFail {
		t.Errorf("want FAIL when admin path accessible, got %s", result.Outcome)
	}
}

func TestEscalation_Error_OnNetworkFailure(t *testing.T) {
	exp := experiments.NewEscalation("/admin", "user-token")
	result := exp.Run("http://example.com", mockError())
	if result.Outcome != chaos.OutcomeError {
		t.Errorf("want ERROR on network failure, got %s", result.Outcome)
	}
}

func TestEscalation_TargetContainsAdminPath(t *testing.T) {
	var capturedURL string
	client := chaos.HTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		capturedURL = req.URL.String()
		return &http.Response{
			StatusCode: 403,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	exp := experiments.NewEscalation("/admin/users", "token")
	exp.Run("http://example.com", client)
	if !strings.HasSuffix(capturedURL, "/admin/users") {
		t.Errorf("expected URL to end with /admin/users, got %s", capturedURL)
	}
}

func TestEscalation_DefaultPath(t *testing.T) {
	exp := experiments.NewEscalation("", "")
	if exp.Name() != "permission-escalation" {
		t.Errorf("unexpected name: %s", exp.Name())
	}
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

func TestRunner_RunAll_CollectsAllResults(t *testing.T) {
	exps := []chaos.Experiment{
		&experiments.ExpiredJWTExperiment{},
		experiments.NewRevokedAPIKey(),
	}
	runner := chaos.NewRunner(mockStatus(401), exps...)
	results := runner.RunAll("http://example.com")
	if len(results) != 2 {
		t.Errorf("want 2 results, got %d", len(results))
	}
}

func TestRunner_RunOne_ByName(t *testing.T) {
	runner := chaos.NewRunner(
		mockStatus(401),
		&experiments.ExpiredJWTExperiment{},
		experiments.NewRevokedAPIKey(),
	)
	result, ok := runner.RunOne("http://example.com", "revoked-api-key")
	if !ok {
		t.Fatal("RunOne returned false for known experiment")
	}
	if result.ExperimentName != "revoked-api-key" {
		t.Errorf("unexpected experiment name: %s", result.ExperimentName)
	}
}

func TestRunner_RunOne_UnknownName_ReturnsFalse(t *testing.T) {
	runner := chaos.NewRunner(mockStatus(200), &experiments.ExpiredJWTExperiment{})
	_, ok := runner.RunOne("http://example.com", "nonexistent")
	if ok {
		t.Error("RunOne should return false for unknown experiment")
	}
}

func TestRunner_RunAll_AllPass(t *testing.T) {
	runner := chaos.NewRunner(
		mockStatus(401),
		&experiments.ExpiredJWTExperiment{},
		experiments.NewRevokedAPIKey(),
	)
	results := runner.RunAll("http://example.com")
	for _, r := range results {
		if r.Outcome != chaos.OutcomePass {
			t.Errorf("experiment %s: want PASS, got %s", r.ExperimentName, r.Outcome)
		}
	}
}

func TestRunner_Experiments_ReturnsList(t *testing.T) {
	runner := chaos.NewRunner(
		mockStatus(200),
		&experiments.ExpiredJWTExperiment{},
		experiments.NewRateLimit(5),
	)
	if len(runner.Experiments()) != 2 {
		t.Errorf("want 2 experiments, got %d", len(runner.Experiments()))
	}
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

func TestReport_New_SummaryCounts(t *testing.T) {
	results := []chaos.Result{
		{Outcome: chaos.OutcomePass},
		{Outcome: chaos.OutcomePass},
		{Outcome: chaos.OutcomeFail},
		{Outcome: chaos.OutcomeError},
	}
	r := report.New("http://example.com", results)
	if r.Summary.Pass != 2 {
		t.Errorf("want Pass=2, got %d", r.Summary.Pass)
	}
	if r.Summary.Fail != 1 {
		t.Errorf("want Fail=1, got %d", r.Summary.Fail)
	}
	if r.Summary.Errors != 1 {
		t.Errorf("want Errors=1, got %d", r.Summary.Errors)
	}
	if r.Summary.Total != 4 {
		t.Errorf("want Total=4, got %d", r.Summary.Total)
	}
}

func TestReport_ToJSON_ValidJSON(t *testing.T) {
	results := []chaos.Result{
		{ExperimentName: "test", Outcome: chaos.OutcomePass, ActualStatus: 401},
	}
	r := report.New("http://example.com", results)
	out, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestReport_ToJSON_ContainsFields(t *testing.T) {
	r := report.New("http://target.example.com", []chaos.Result{})
	out, _ := r.ToJSON()
	for _, field := range []string{"target", "results", "summary", "generated_at"} {
		if !strings.Contains(out, field) {
			t.Errorf("JSON missing field %q", field)
		}
	}
}

func TestReport_ToText_ContainsTarget(t *testing.T) {
	r := report.New("http://staging.example.com", []chaos.Result{})
	text := r.ToText()
	if !strings.Contains(text, "http://staging.example.com") {
		t.Error("text report should contain target URL")
	}
}

func TestReport_ToText_AllPass_ShowsVerified(t *testing.T) {
	results := []chaos.Result{
		{Outcome: chaos.OutcomePass},
		{Outcome: chaos.OutcomePass},
	}
	r := report.New("http://example.com", results)
	text := r.ToText()
	if !strings.Contains(text, "All security controls verified") {
		t.Error("all-pass report should show verification message")
	}
}

func TestReport_ToText_WithFail_ShowsGaps(t *testing.T) {
	results := []chaos.Result{
		{Outcome: chaos.OutcomeFail, ExperimentName: "expired-jwt", Message: "test"},
	}
	r := report.New("http://example.com", results)
	text := r.ToText()
	if !strings.Contains(text, "Security gaps detected") {
		t.Error("report with failures should show gaps message")
	}
}

func TestReport_ToText_ContainsExperimentName(t *testing.T) {
	results := []chaos.Result{
		{
			ExperimentName: "rate-limit-breach",
			Outcome:        chaos.OutcomePass,
			Message:        "rate limit triggered at request 5",
			ActualStatus:   429,
		},
	}
	r := report.New("http://example.com", results)
	text := r.ToText()
	if !strings.Contains(text, "rate-limit-breach") {
		t.Error("text report should contain experiment name")
	}
}
