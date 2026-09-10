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

	// 1. dictionary words + common passwords (with l33t and digit suffixes)
	dictMatches(pw, &matches)

	// 2. keyboard + numpad runs (qwerty, 789456123, 147258369...)
	add(keyboardRuns(runes))

	// 3. sequences: digits, alpha, uppercase, keyboard
	add(sequenceRun(runes, "0123456789", "seq_num", 100, true))
	add(sequenceRun(runes, "abcdefghijklmnopqrstuvwxyz", "seq_alpha", 676, false))
	add(sequenceRun(runes, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "seq_alpha", 676, false))
	add(sequenceRun(runes, "qwertyuiopasdfghjklzxcvbnm", "seq_kbd", 1000, false))

	// 4. years (1900-2099)
	add(yearRun(runes))

	// 5. repeated substrings ("ababab", "aaaa") and grouped digits ("111222333")
	add(repeatRun(runes))
	add(groupedRepeatRun(runes))

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
// Trailing digits are always stripped for lookup ("password123" -> "password").
// Returns (changed, decoded).
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
	changed := alt != word

	// candidate forms: leet-decoded, then trailing digits stripped
	forms := []string{alt, strings.TrimRight(alt, "0123456789")}
	if changed {
		forms = append(forms, word, strings.TrimRight(word, "0123456789"))
	}
	for _, f := range forms {
		if _, ok := commonPasswords[f]; ok {
			return changed, f
		}
		if _, ok := englishWords[f]; ok {
			return changed, f
		}
	}
	return changed, word
}

// keyboardRuns finds runs of 3+ keys in qwerty rows or the numeric keypad
// (rows 789456123/741852963, columns 147258369, diagonals 159357).
func keyboardRuns(runes []rune) candidate {
	rows := []string{
		"qwertyuiopasdfghjklzxcvbnm", "1234567890", "!@#$%^&*()",
		"789456123", "741852963", "147258369", "159357",
	}
	prevR, nextR := -1, -1
	_ = prevR
	_ = nextR
	var best candidate
	for ri := 0; ri < len(runes); ri++ {
		cur := 1
		for rj := ri + 1; rj < len(runes); rj++ {
			ok := false
			for _, row := range rows {
				prev := strings.IndexRune(row, runes[rj-1])
				next := strings.IndexRune(row, runes[rj])
				if prev >= 0 && next >= 0 && (next == prev+1 || next == prev-1) {
					ok = true
					break
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

// sequenceRun finds consecutive ascending/descending runs in a sorted alphabet.
// wrap allows digit sequences like 7890 / 09876 to keep matching.
func sequenceRun(runes []rune, alphabet, typ string, perChar float64, wrap bool) candidate {
	idx := func(r rune) int { return strings.IndexRune(alphabet, r) }
	adj := func(a, b rune) (int, int) {
		pa, pb := idx(a), idx(b)
		if pa < 0 || pb < 0 {
			return -1, -1
		}
		diff := pb - pa
		if wrap && diff == -9 { // digit wrap 9->0
			return 1, -1
		}
		if wrap && diff == 9 { // digit wrap 0->9 (descending)
			return -1, 1
		}
		return pa, pb
	}
	var best candidate
	for i := 0; i < len(runes); i++ {
		bestLen := 1
		for _, dir := range []int{1, -1} {
			cur := 1
			for j := i + 1; j < len(runes); j++ {
				a, b := adj(runes[j-1], runes[j])
				if a < 0 || b < 0 {
					break
				}
				if (b == a+1 && dir == 1) || (b == a-1 && dir == -1) {
					cur++
				} else {
					break
				}
			}
			if cur > bestLen {
				bestLen = cur
			}
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

// yearRun flags common years 1900-2099, a very common human pattern.
func yearRun(runes []rune) candidate {
	for i := 0; i+4 <= len(runes); i++ {
		if !allDigits(string(runes[i : i+4])) {
			continue
		}
		y := 0
		for _, r := range runes[i : i+4] {
			y = y*10 + int(r-'0')
		}
		if y >= 1900 && y <= 2099 {
			g := 199.0 // ~200 possible years
			return candidate{
				start: i, end: i + 4, typ: "seq_num",
				guesses:     g,
				guessesLog2: lg2(g),
			}
		}
	}
	return candidate{}
}

// groupedRepeatRun catches grouped digit/key patterns like "111222333",
// "qqqwww", "121212" that single-char repeat runs miss.
func groupedRepeatRun(runes []rune) candidate {
	var best candidate
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
			if j-i > best.end-best.start {
				best = candidate{start: i, end: j}
			}
		}
	}
	if best.end-best.start >= 1 {
		l := float64(best.end - best.start)
		g := 100 * math.Pow(2, l-3)
		best.typ = "repeat"
		best.guesses = g
		best.guessesLog2 = lg2(g)
		return best
	}
	return candidate{}
}

// repeatRun finds runs of the same character ("aaaa", "11111").
func repeatRun(runes []rune) candidate {
	var best candidate
	for i := 0; i < len(runes); i++ {
		j := i
		for j < len(runes) && runes[j] == runes[i] {
			j++
		}
		if j-i >= 3 && j-i > best.end-best.start {
			best = candidate{start: i, end: j}
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
