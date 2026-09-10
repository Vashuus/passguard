// Package breach checks whether a password has appeared in a known data
// breach using the HaveIBeenPwned "Pwned Passwords" API in a
// k-anonymous way: only the first 5 hex chars of its SHA-1 hash leave
// this machine, so the password itself is never transmitted.
package breach

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const endpoint = "https://api.pwnedpasswords.com/range/"

// Client queries the Pwned Passwords API.
type Client struct {
	hc     *http.Client
	pretty bool
}

// Option customizes the client.
type Option func(*Client)

// WithTimeout sets the HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.hc.Timeout = d }
}

// New returns a ready-to-use client.
func New(opts ...Option) *Client {
	c := &Client{hc: &http.Client{Timeout: 10 * time.Second}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// CheckReport holds the outcome of a pwned-check.
type CheckReport struct {
	Hash      string `json:"hash"`
	Count     int    `json:"count"`
	Found     bool   `json:"found"`
	Truncated bool   `json:"truncated"` // SHA-1 prefix used
}

// Check determines whether pw appears in breach data. The plain password
// is never sent over the wire.
func (c *Client) Check(pw string) (CheckReport, error) {
	sum := sha1.Sum([]byte(pw))
	full := hex.EncodeToString(sum[:])
	prefix, suffix := strings.ToUpper(full[:5]), strings.ToUpper(full[5:])
	rep := CheckReport{Hash: full, Truncated: true}

	u := endpoint + prefix
	resp, err := c.hc.Get(u)
	if err != nil {
		return rep, fmt.Errorf("pwnedpasswords: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rep, fmt.Errorf("pwnedpasswords: estado %s", resp.Status)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == suffix {
			cnt := 0
			fmt.Sscanf(parts[1], "%d", &cnt)
			rep.Found = true
			rep.Count = cnt
			break
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return rep, fmt.Errorf("pwnedpasswords: lectura: %w", err)
	}
	return rep, nil
}
