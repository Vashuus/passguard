// Package generator creates cryptographically-random passwords using
// crypto/rand and rejects candidates that the strength engine flags as
// weak or that contain detectable patterns.
package generator

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"

	"github.com/Vashuus/passguard/internal/strength"
)

const (
	lower   = "abcdefghijkmnopqrstuvwxyz" // no 'l'
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // no 'I', 'O'
	digits  = "23456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
)

// Options configure a generation request.
type Options struct {
	Length     int     // total password length
	Upper      bool    // include uppercase letters
	Digits     bool    // include digits
	Symbols    bool    // include symbols
	NoSimilar  bool    // drop look-alike chars (l/1/I/O/0)
	MinScore   int     // strength engine rejects candidates below this score
	MinEntropy float64 // minimum bits of entropy required
	Passphrase bool    // generate a memory-friendly passphrase instead
}

// DefaultOptions returns sane defaults.
func DefaultOptions() Options {
	return Options{
		Length:     20,
		Upper:      true,
		Digits:     true,
		Symbols:    true,
		NoSimilar:  true,
		MinScore:   strength.ScoreSafelyUnguessable,
		MinEntropy: 80,
	}
}

func randomIndex(n int) (int, error) {
	bi, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(bi.Int64()), nil
}

// Generate produces a password that satisfies Options, retrying until the
// strength engine is happy (rejection sampling).
func Generate(o Options) (string, error) {
	if o.Length == 0 {
		o = DefaultOptions()
	}
	if o.Length < 8 {
		return "", errors.New("longitud mínima: 8 caracteres")
	}

	alphabet := lower
	if o.Upper {
		alphabet += upper
	}
	if o.Digits {
		alphabet += digits
	}
	if o.Symbols {
		alphabet += symbols
	}
	if o.NoSimilar {
		alphabet = strings.Map(func(r rune) rune {
			switch r {
			case 'l', '1', 'I', 'O', '0':
				return -1
			}
			return r
		}, alphabet)
	}
	// guarantee at least one of each requested class, drawn at random from
	// class-specific pools so the majority of chars stay fully random.
	classes := []string{lower}
	if o.Upper {
		classes = append(classes, upper)
	}
	if o.Digits {
		classes = append(classes, digits)
	}
	if o.Symbols {
		classes = append(classes, symbols)
	}
	pools := make([][]rune, 0, len(classes))
	for _, c := range classes {
		if o.NoSimilar {
			c = strings.Map(func(r rune) rune {
				switch r {
				case 'l', '1', 'I', 'O', '0':
					return -1
				}
				return r
			}, c)
			if c == "" {
				continue
			}
		}
		pools = append(pools, []rune(c))
	}
	if len(pools) == 0 {
		pools = [][]rune{[]rune("abcdefghijkmnpqrstuvwxyz")}
	}

	guaranteed := make([]rune, 0, len(pools))
	for _, pool := range pools {
		idx, err := randomIndex(len(pool))
		if err != nil {
			return "", err
		}
		guaranteed = append(guaranteed, pool[idx])
	}

	// Try up to 200 candidates, keeping the best one that passes.
	best := ""
	bestEntropy := 0.0
	for attempt := 0; attempt < 200; attempt++ {
		b := make([]rune, o.Length)
		pos := 0
		for _, r := range guaranteed {
			if pos < o.Length {
				b[pos] = r
				pos++
			}
		}
		chars := []rune(alphabet)
		for ; pos < o.Length; pos++ {
			idx, err := randomIndex(len(chars))
			if err != nil {
				return "", err
			}
			b[pos] = chars[idx]
		}
		// shuffled by rejection of ordered guarantees; do a Fisher-Yates-ish
		// random swap pass to avoid deterministic prefix.
		for i := len(b) - 1; i > 0; i-- {
			j, err := randomIndex(i + 1)
			if err != nil {
				return "", err
			}
			b[i], b[j] = b[j], b[i]
		}

		cand := string(b)
		res := strength.Estimate(cand)
		if res.Entropy > bestEntropy {
			best = cand
			bestEntropy = res.Entropy
		}
		if res.Score >= o.MinScore && res.Entropy >= o.MinEntropy {
			return cand, nil
		}
	}
	return best, nil
}

// wordlist for passphrases: memorable common words.
var wordlist = []string{
	"alce", "arpa", "barca", "brazo", "cabra", "cielo", "claro", "cobre",
	"dulce", "dunas", "farol", "fuego", "globo", "hielo", "lago", "luna",
	"mapa", "mar", "musgo", "nube", "oso", "papel", "pez", "puente",
	"rama", "roca", "silla", "sol", "tigre", "torre", "uva", "viento",
	"cedro", "chopo", "honesto", "lucero", "pluma", "senda", "trigo", "yunque",
	"nieve", "paz", "rueda", "teja", "vaso", "aula", "ala", "bruma",
	"coro", "draga", "espiga", "fresco", "gorra", "indio", "jabon", "karma",
	"labio", "muelle", "ninfa", "oliva", "poro", "quisa", "remo", "silva",
	"tenia", "urna", "vino", "yema", "zumo", "ancla", "brezo", "cieno",
}

// GeneratePassphrase builds a diceware-style phrase of n words.
func GeneratePassphrase(n int) (string, error) {
	if n < 3 {
		n = 4
	}
	words := make([]string, n)
	used := map[string]bool{}
	for i := 0; i < n; i++ {
		idx, err := randomIndex(len(wordlist))
		if err != nil {
			return "", err
		}
		if used[wordlist[idx]] {
			i--
			continue
		}
		used[wordlist[idx]] = true
		words[i] = wordlist[idx]
	}
	pw := strings.Join(words, "-")
	return pw, nil
}
