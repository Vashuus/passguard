package strength

import (
	"strings"
	"testing"
)

func TestEstimateWeakClassics(t *testing.T) {
	weak := []string{"123456", "password", "qwerty", "12345678", "iloveyou", "aaaaaaaa", "abc123"}
	for _, pw := range weak {
		res := Estimate(pw)
		if res.Score > 2 {
			t.Errorf("%q: score=%d, entropía=%.1f, esperábamos débil", pw, res.Score, res.Entropy)
		}
		if len(res.Patterns) == 0 {
			t.Errorf("%q: no se detectó ningún patrón débil", pw)
		}
	}
}

func TestEstimateKeyboardAndSequence(t *testing.T) {
	for _, pw := range []string{"qwertyuiop", "zxcvbnm", "1234567890", "asdfghjkl", "qazwsxedc"} {
		res := Estimate(pw)
		if res.Score > 2 {
			t.Errorf("%q: score=%d, debe ser débil por patrones", pw, res.Score)
		}
	}
}

func TestEstimateRepeated(t *testing.T) {
	// periodic and runs
	for _, pw := range []string{"abababab", "aaaaaaaaa", "12121212"} {
		res := Estimate(pw)
		if res.Score > 2 {
			t.Errorf("%q: score=%d, repeticiones deberían penalizar", pw, res.Score)
		}
	}
}

func TestEstimateLeetDictionary(t *testing.T) {
	pw := "p4ssw0rd"
	res := Estimate(pw)
	if res.Score > 2 {
		t.Errorf("%q: l33t del diccionario debería ser débil, score=%d", pw, res.Score)
	}
	found := false
	for _, p := range res.Patterns {
		if p.Type == "dict" {
			found = true
		}
	}
	if !found {
		t.Errorf("%q: no se detectó la palabra con l33t", pw)
	}
}

func TestEstimateStrong(t *testing.T) {
	strong := []string{
		"Tr0ub4dor&3k#A9xQ2vM8pZ!",
		"Kx9#mQz2$vL7@nWp4!cT8",
		"73!xQwE9#LmZ4@kDp7^RtB2",
	}
	for _, pw := range strong {
		res := Estimate(pw)
		if res.Score < 3 || res.Entropy < 80 {
			t.Errorf("%q: score=%d entropía=%.1f, debe ser fuerte", pw, res.Score, res.Entropy)
		}
	}
}

func TestEstimatePassphrase(t *testing.T) {
	res := Estimate("correct-horse-battery-staple")
	// words that are not all in our dictionary, so separation matters
	if res.Score < 3 && res.Entropy < 60 {
		t.Errorf("passphrase: score=%d entropía=%.1f", res.Score, res.Entropy)
	}
}

func TestEntropyMonotonicLength(t *testing.T) {
	short := Estimate(strings.Repeat("xR9!", 3))
	long := Estimate(strings.Repeat("xR9!", 6))
	if long.Entropy <= short.Entropy {
		t.Errorf("entropía debería crecer con la longitud: %f <= %f", long.Entropy, short.Entropy)
	}
}

func TestCrackTimeFormatting(t *testing.T) {
	if crackTime(1e2) != "instantáneo" {
		t.Errorf("crackTime(100) = %q", crackTime(1e2))
	}
}
