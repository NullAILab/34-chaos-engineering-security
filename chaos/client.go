// Package chaos provides the core types and interfaces for the chaos
// engineering security tool.
package chaos

import "net/http"

// HTTPClient is an injectable HTTP client used by all experiments.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClientFunc lets an ordinary function satisfy HTTPClient.
type HTTPClientFunc func(*http.Request) (*http.Response, error)

// Do implements HTTPClient.
func (f HTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}
