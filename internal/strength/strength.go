// Package strength estimates password strength using a zxcvbn-inspired
// model: character class coverage, dictionary words, l33t substitutions,
// keyboard patterns, number sequences and repeated substrings.
package strength

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

// Score bands mirror zxcvbn: number of guesses required to crack the
// password and an equivalent human-readable ranking.
const (
	ScoreTooGuessable      = 0 // guesses < 1e3
	ScoreVeryGuessable     = 1 // guesses < 1e6
	ScoreSomewhatGuessable = 2 // guesses < 1e8
	ScoreSafelyUnguessable = 3 // guesses < 1e10
	ScoreVeryUnguessable   = 4 // guesses >= 1e10
)

// Pattern describes a weakness found inside the password.
type Pattern struct {
	Token    string  `json:"token"`
	Type     string  `json:"type"`
	Guesses  float64 `json:"guesses"`
	Entropy  float64 `json:"entropy"`
	Position int     `json:"position"`
}

// Result is the outcome of estimating a password's strength.
type Result struct {
	Score       int       `json:"score"`
	Entropy     float64   `json:"entropy"` // bits
	Guesses     float64   `json:"guesses"`
	CrackTime   string    `json:"crack_time"`
	Charset     int       `json:"charset_size"`
	Length      int       `json:"length"`
	Patterns    []Pattern `json:"patterns"`
	Warning     string    `json:"warning"`
	Suggestions []string  `json:"suggestions"`
}

// charClasses returns how many of the main ASCII classes are present.
func charClasses(s string) (lower, upper, digit, symbol bool) {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	return
}

// charsetSize counts the distinct characters in s.
func charsetSize(s string) int {
	set := map[rune]struct{}{}
	for _, r := range s {
		set[r] = struct{}{}
	}
	return len(set)
}

// bruteforceGuesses is the shallow per-character guess count for a token.
func bruteforceGuesses(s string) float64 {
	if s == "" {
		return 1
	}
	cs := float64(charsetSize(s))
	if cs < 2 {
		cs = 2
	}
	return math.Pow(cs, float64(len([]rune(s))))
}

// estimate performs pattern matching and returns the full Result.
func estimate(pw string) Result {
	runes := []rune(pw)
	res := Result{Length: len(runes), Charset: charsetSize(pw)}
	_, _, hasDigit, hasSymbol := charClasses(pw)

	matches := findMatches(pw)
	dp := make([]float64, len(runes)+1)
	chosen := make([]Pattern, len(runes)+1)
	for i := range dp {
		dp[i] = math.Inf(1)
	}
	chosenHas := make([]bool, len(runes)+1)
	dp[0] = 0

	// per-character brute-force guess count over the observed charset
	bt := math.Log2(float64(charsetSize(pw)))
	if bt < 1 {
		bt = 1
	}
	for i := 1; i <= len(runes); i++ {
		if math.IsInf(dp[i-1], 1) {
			break
		}
		dp[i] = dp[i-1] + bt
		for _, m := range matches {
			if m.end != i {
				continue
			}
			cand := dp[m.start] + m.guessesLog2
			if cand < dp[i] {
				dp[i] = cand
				chosen[i] = Pattern{
					Token:    string(runes[m.start:m.end]),
					Type:     m.typ,
					Guesses:  m.guesses,
					Entropy:  m.guessesLog2,
					Position: m.start,
				}
				chosenHas[i] = true
			}
		}
	}
	res.Entropy = dp[len(runes)]
	res.Guesses = math.Pow(2, dp[len(runes)])
	if res.Guesses == math.Inf(1) || res.Guesses > 1e300 {
		res.Guesses = 1e300
	}

	// rebuild selected patterns in order
	for i := 1; i <= len(runes); i++ {
		if chosenHas[i] {
			res.Patterns = append(res.Patterns, chosen[i])
		}
	}
	keepTop(res.Patterns)

	// previous characters overlap? keep only the longest top patterns
	res.Patterns = dedupeOverlap(res.Patterns)

	res.Score = scoreFromGuesses(res.Guesses)
	res.CrackTime = crackTime(res.Guesses)

	if !hasDigit || len(runes) < 8 {
		res.Warning = "Too short or no digits: it can be brute-forced."
		res.Suggestions = append(res.Suggestions,
			"Use at least 12-16 characters.",
			"Mix lowercase, UPPERCASE, digits and symbols.",
			"Avoid dictionary words and keyboard patterns (qwerty, 1234).")
	}
	if hasSymbol && res.Entropy < 60 {
		res.Suggestions = append(res.Suggestions, "Consider a passphrase of 4+ words separated by spaces.")
	}
	if len(runes) >= 12 && res.Score >= 3 {
		res.Warning = "Solid password."
		res.Suggestions = append(res.Suggestions, "Store it in a password manager (you can't memorize them all).")
	}
	return res
}

// Estimate returns an exported account of the password's strength.
func Estimate(pw string) Result {
	return estimate(pw)
}

func scoreFromGuesses(g float64) int {
	switch {
	case g < 1e3:
		return ScoreTooGuessable
	case g < 1e6:
		return ScoreVeryGuessable
	case g < 1e8:
		return ScoreSomewhatGuessable
	case g < 1e10:
		return ScoreSafelyUnguessable
	default:
		return ScoreVeryUnguessable
	}
}

func crackTime(g float64) string {
	// guesses/second typical for an offline attacker doing fast hashing.
	const gps = 1e10
	sec := g / gps
	units := []struct {
		v float64
		s string
	}{{60 * 60 * 24, "days"}, {60 * 60, "hours"}, {60, "minutes"}, {1, "seconds"}}
	if sec < 1 {
		return "instant"
	}
	for _, u := range units {
		if sec >= u.v {
			v := sec / u.v
			return fmt.Sprintf("%.1f %s", v, u.s)
		}
	}
	if sec > 365*24*3600*100 {
		return ">100 years"
	}
	if sec > 24*3600*365 {
		return fmt.Sprintf("%.1f years", sec/(24*3600*365))
	}
	return "instant"
}

// keepTop sorts patterns so lowest-guess (most severe) come first.
func keepTop(p []Pattern) {
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].Guesses == p[j].Guesses {
			return len(p[i].Token) > len(p[j].Token)
		}
		return p[i].Guesses < p[j].Guesses
	})
}

func dedupeOverlap(p []Pattern) []Pattern {
	if len(p) < 2 {
		return p
	}
	out := p[:1]
	for _, pat := range p[1:] {
		last := out[len(out)-1]
		a1 := last.Position + len([]rune(last.Token))
		b0, b1 := pat.Position, pat.Position+len([]rune(pat.Token))
		_ = b1
		if b0 >= a1 { // non-overlapping
			out = append(out, pat)
			continue
		}
		// overlapping: keep the one with the lowest guess count
		if pat.Guesses < last.Guesses {
			out[len(out)-1] = pat
		}
	}
	return out
}

// entropyPerChar returns an average brute-force bits-per-character value.
func entropyPerChar(s string) float64 {
	n := float64(charsetSize(s))
	if n <= 1 {
		return 2
	}
	return math.Log2(n)
}

var _ = unicode.IsUpper
var _ = strings.ToLower
