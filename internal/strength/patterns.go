package strength

import (
	"math"
	"strings"
)

// candidate is a cluster of characters over which a pattern applies.
type candidate struct {
	start, end  int // uint offsets over []rune
	typ         string
	guesses     float64
	guessesLog2 float64
}

func lg2(v float64) float64 {
	if v <= 0 {
		return 0
	}
	return math.Log2(v)
}

// findMatches locates weak patterns inside pw. Matches are non overlapping.
func findMatches(pw string) []candidate {
	runes := []rune(pw)
	var matches []candidate
	add := func(c candidate) {
		if c.end <= c.start {
			return
		}
		matches = append(matches, c)
	}

	// 1. dictionary words + common passwords (with l33t)
	dictMatches(pw, &matches)

	// 2. keyboard runs (qwerty)
	add(keyboardRuns(runes))

	// 3. numeric sequences like 1234, 654321
	add(sequenceRun(runes, "0123456789", "seq_num", 100))
	add(sequenceRun(runes, "abcdefghijklmnopqrstuvwxyz", "seq_alpha", 676))
	add(sequenceRun(runes, "qwertyuiopasdfghjklzxcvbnm", "seq_kbd", 1000))

	// 4. repeated substrings ("ababab", "aaaa")
	add(repeatRun(runes))

	return matches
}

// guessPerChar returns a safe guess-per-character for a given type.
func guessPerChar(typ string) float64 {
	switch typ {
	case "seq_num":
		return 100 // 10 digits * 10 orders
	case "seq_alpha":
		return 676 // 26 letters * 26 orders
	case "seq_kbd":
		return 1000
	case "keyboard":
		return 300
	case "repeat":
		return 100
	default:
		return 10
	}
}

// matcher helper for dictionary + l33t.
func dictMatches(pw string, out *[]candidate) {
	runes := []rune(pw)
	lower := strings.ToLower(pw)
	for i := 0; i < len(runes); i++ {
		for j := i + 1; j <= len(runes) && j-i <= 20; j++ {
			word := lower[i:j]
			if word == "" {
				continue
			}
			leetOK, base := unleet(word)
			if info, found := lookup(base); found {
				wordForm := base
				// compute how many chars were altered by l33t
				l33tCount := 0
				for k := 0; k < len(word); k++ {
					if leetOK && k < len(base) && word[k] != base[k] {
						l33tCount++
					}
				}
				if !leetOK {
					wordForm = word
				}
				guesses := info.guesses
				up := 1
				tok := string(runes[i:j])
				if tok != wordForm {
					for _, r := range tok {
						if r >= 'A' && r <= 'Z' {
							up *= 2
						}
					}
				}
				if up > 1 {
					guesses *= float64(up)
				}
				guesses *= math.Pow(2, float64(l33tCount))
				*out = append(*out, candidate{
					start: i, end: j, typ: "dict",
					guesses:     guesses,
					guessesLog2: lg2(guesses),
				})
			}
		}
	}
}

// lookup consults the embedded dictionaries.
func lookup(word string) (struct{ guesses float64 }, bool) {
	if g, ok := commonPasswords[word]; ok {
		return struct{ guesses float64 }{g}, true
	}
	if _, ok := englishWords[word]; ok {
		// ~1800 common words
		return struct{ guesses float64 }{2400}, true
	}
	// short numeric like "1990"
	if len(word) == 4 && allDigits(word) {
		return struct{ guesses float64 }{2000}, true
	}
	return struct{ guesses float64 }{0}, false
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// unleet reverses common leetspeak substitutions if doing so yields a word.
// Returns (ok, decoded).
func unleet(word string) (bool, string) {
	table := []struct{ from, to string }{
		{"4", "a"}, {"@", "a"}, {"8", "b"}, {"3", "e"}, {"6", "g"},
		{"1", "i"}, {"!", "i"}, {"0", "o"}, {"$", "s"}, {"5", "s"},
		{"7", "t"}, {"+", "t"}, {"9", "g"},
	}
	alt := word
	for _, s := range table {
		alt = strings.ReplaceAll(alt, s.from, s.to)
	}
	if alt == word {
		return false, word
	}
	if _, ok := commonPasswords[alt]; ok {
		return true, alt
	}
	if _, ok := englishWords[alt]; ok {
		return true, alt
	}
	// try removing trailing digits (p@ssword123 -> password)
	trimmed := strings.TrimRight(alt, "0123456789")
	if _, ok := commonPasswords[trimmed]; ok {
		return true, trimmed
	}
	return false, word
}

// keyboardRuns finds runs of 3+ keys in qwerty rows.
func keyboardRuns(runes []rune) candidate {
	rows := []string{"qwertyuiopasdfghjklzxcvbnm", "1234567890", "!@#$%^&*()"}
	var best candidate
	for ri := 0; ri < len(runes); ri++ {
		cur := 1
		for rj := ri + 1; rj < len(runes); rj++ {
			ok := false
			for _, row := range rows {
				prev := strings.IndexRune(row, runes[rj-1])
				next := strings.IndexRune(row, runes[rj])
				if prev >= 0 && next >= 0 && (next == prev+1 || next == prev-1 || abs(next-prev) >= len(row)-1) {
					// forward/backward adjacency (wraparound for digits row)
					if prev == 0 && next == len(row)-1 {
						break
					}
					if next == prev+1 || next == prev-1 {
						ok = true
						break
					}
				}
			}
			if !ok {
				break
			}
			cur++
		}
		if cur >= 3 && cur > best.end-best.start {
			best = candidate{start: ri, end: ri + cur}
		}
	}
	if best.end-best.start >= 3 {
		l := float64(best.end - best.start)
		g := 300 * math.Pow(2, l-3)
		best.typ = "keyboard"
		best.guesses = g
		best.guessesLog2 = lg2(g)
		return best
	}
	return candidate{}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// sequenceRun finds consecutive ascending/descending runs in a sorted alphabet.
func sequenceRun(runes []rune, alphabet, typ string, perChar float64) candidate {
	idx := func(r rune) int { return strings.IndexRune(alphabet, r) }
	var best candidate
	for i := 0; i < len(runes); i++ {
		asc, desc := 1, 1
		for j := i + 1; j < len(runes); j++ {
			prev, cur := idx(runes[j-1]), idx(runes[j])
			if prev < 0 || cur < 0 {
				break
			}
			if cur == prev+1 {
				asc++
			} else {
				break
			}
		}
		for j := i + 1; j < len(runes); j++ {
			prev, cur := idx(runes[j-1]), idx(runes[j])
			if prev < 0 || cur < 0 {
				break
			}
			if cur == prev-1 {
				desc++
			} else {
				break
			}
		}
		bestLen := asc
		if desc > asc {
			bestLen = desc
		}
		if bestLen >= 3 && bestLen > best.end-best.start {
			best = candidate{start: i, end: i + bestLen}
		}
	}
	if best.end-best.start >= 3 {
		l := float64(best.end - best.start)
		g := perChar * math.Pow(2, l-3)
		best.typ = typ
		best.guesses = g
		best.guessesLog2 = lg2(g)
		return best
	}
	return candidate{}
}

// repeatRun finds a substring repeated 2+ times, and runs of identical chars.
func repeatRun(runes []rune) candidate {
	var best candidate
	// runs of the same char
	for i := 0; i < len(runes); i++ {
		j := i
		for j < len(runes) && runes[j] == runes[i] {
			j++
		}
		if j-i >= 3 && j-i > best.end-best.start {
			best = candidate{start: i, end: j}
		}
	}
	// periodic repeats over 2-6 length seeds
	for seed := 2; seed <= 6; seed++ {
		if seed*2 > len(runes) {
			break
		}
		for i := 0; i+seed*2 <= len(runes); i++ {
			a := string(runes[i : i+seed])
			if string(runes[i+seed:i+2*seed]) != a {
				continue
			}
			j := i + 2*seed
			for j+seed <= len(runes) && string(runes[j:j+seed]) == a {
				j += seed
			}
			if j-i >= seed*2 && j-i > best.end-best.start {
				best = candidate{start: i, end: j}
			}
		}
	}
	if best.end-best.start >= 3 {
		l := float64(best.end - best.start)
		g := 100 * math.Pow(2, l-3)
		best.typ = "repeat"
		best.guesses = g
		best.guessesLog2 = lg2(g)
		return best
	}
	return candidate{}
}

// FindAll is the exported token entry point (used for debugging/tests).
func normalizeForMatch(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
