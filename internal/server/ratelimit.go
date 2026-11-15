// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// The limiters below live in process memory. They reset on restart and are
// not shared between server instances. That is acceptable for the supported
// single-instance deployment; a multi-instance deployment needs a limit at
// the reverse proxy as well.

// rateLimiter is a token bucket per key.
type rateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	burst   float64
	perSec  float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(now func() time.Time, burst, perSec float64) *rateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{now: now, burst: burst, perSec: perSec, buckets: map[string]*bucket{}}
}

// allow takes one token. When none is left it returns the wait time.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= 50000 {
			l.pruneLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.perSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// pruneLocked drops buckets that have refilled completely.
func (l *rateLimiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= 50000 {
		l.buckets = map[string]*bucket{}
	}
}

// lockouts applies an exponential backoff to failed logins per
// username and client IP: the first 4 failures are free; failure n >= 5
// locks the pair for 30 s * 2^(n-5), capped at 15 minutes. A success or one
// hour without failures resets the count.
type lockouts struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*lockState
}

type lockState struct {
	fails int
	until time.Time
	last  time.Time
}

const (
	lockFreeFailures = 4
	lockBase         = 30 * time.Second
	lockMax          = 15 * time.Minute
	lockForget       = time.Hour
)

func newLockouts(now func() time.Time) *lockouts {
	return &lockouts{now: now, m: map[string]*lockState{}}
}

// locked reports whether the key is locked and for how long.
func (l *lockouts) locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil {
		return false, 0
	}
	now := l.now()
	if now.Sub(s.last) > lockForget {
		delete(l.m, key)
		return false, 0
	}
	if now.Before(s.until) {
		return true, s.until.Sub(now)
	}
	return false, 0
}

func (l *lockouts) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) >= 50000 {
		for k, s := range l.m {
			if now.Sub(s.last) > lockForget {
				delete(l.m, k)
			}
		}
		if len(l.m) >= 50000 {
			l.m = map[string]*lockState{}
		}
	}
	s := l.m[key]
	if s == nil || now.Sub(s.last) > lockForget {
		s = &lockState{}
		l.m[key] = s
	}
	s.fails++
	s.last = now
	if s.fails > lockFreeFailures {
		d := lockBase << uint(min(s.fails-lockFreeFailures-1, 10))
		if d > lockMax {
			d = lockMax
		}
		s.until = now.Add(d)
	}
}

func (l *lockouts) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

// metrics holds the operational counters exposed at /metrics. They count
// requests, ingests, and authentication failures. They hold no project
// names, agent names, findings, or other scan detail.
type metrics struct {
	mu       sync.Mutex
	requests map[string]uint64 // "METHOD|code"
	ingests  map[string]uint64 // created | duplicate | rejected
	authFail map[string]uint64 // login | session | token | csrf
}

func newMetrics() *metrics {
	return &metrics{requests: map[string]uint64{}, ingests: map[string]uint64{}, authFail: map[string]uint64{}}
}

func (m *metrics) request(method string, status int) {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		method = "OTHER" // keep label values bounded
	}
	m.mu.Lock()
	m.requests[fmt.Sprintf("%s|%d", method, status)]++
	m.mu.Unlock()
}

func (m *metrics) ingest(result string) {
	m.mu.Lock()
	m.ingests[result]++
	m.mu.Unlock()
}

func (m *metrics) authFailure(kind string) {
	m.mu.Lock()
	m.authFail[kind]++
	m.mu.Unlock()
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// write renders the Prometheus text exposition format.
func (m *metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP agentgov_http_requests_total HTTP requests by method and status code.")
	fmt.Fprintln(w, "# TYPE agentgov_http_requests_total counter")
	for _, k := range sortedKeys(m.requests) {
		var method string
		var code int
		for i := 0; i < len(k); i++ {
			if k[i] == '|' {
				method = k[:i]
				fmt.Sscanf(k[i+1:], "%d", &code)
				break
			}
		}
		fmt.Fprintf(w, "agentgov_http_requests_total{method=%q,code=\"%d\"} %d\n", method, code, m.requests[k])
	}
	fmt.Fprintln(w, "# HELP agentgov_scan_ingests_total Scan uploads by result.")
	fmt.Fprintln(w, "# TYPE agentgov_scan_ingests_total counter")
	for _, k := range sortedKeys(m.ingests) {
		fmt.Fprintf(w, "agentgov_scan_ingests_total{result=%q} %d\n", k, m.ingests[k])
	}
	fmt.Fprintln(w, "# HELP agentgov_auth_failures_total Authentication and CSRF failures by kind.")
	fmt.Fprintln(w, "# TYPE agentgov_auth_failures_total counter")
	for _, k := range sortedKeys(m.authFail) {
		fmt.Fprintf(w, "agentgov_auth_failures_total{kind=%q} %d\n", k, m.authFail[k])
	}
}
