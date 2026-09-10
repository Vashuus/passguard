package generator

import (
	"strings"
	"testing"

	"github.com/Vashuus/passguard/internal/strength"
)

func TestGenerateClasses(t *testing.T) {
	o := DefaultOptions()
	o.Length = 20
	pw, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != o.Length {
		t.Fatalf("longitud %d != %d", len(pw), o.Length)
	}
	has := func(pred func(r byte) bool) bool {
		for i := 0; i < len(pw); i++ {
			if pred(pw[i]) {
				return true
			}
		}
		return false
	}
	if !has(func(r byte) bool { return r >= 'A' && r <= 'Z' }) {
		t.Errorf("sin mayúsculas: %q", pw)
	}
	if !has(func(r byte) bool { return r >= '2' && r <= '9' }) {
		t.Errorf("sin dígitos: %q", pw)
	}
	if !has(func(r byte) bool {
		return strings.ContainsRune("!@#$%^&*()-_=+[]{};:,.<>?", rune(r))
	}) {
		t.Errorf("sin símbolos: %q", pw)
	}
	res := strength.Estimate(pw)
	if res.Score < o.MinScore {
		t.Errorf("score %d < %d para %q", res.Score, o.MinScore, pw)
	}
	if res.Entropy < o.MinEntropy {
		t.Errorf("entropía %.1f < %.1f para %q", res.Entropy, o.MinEntropy, pw)
	}
}

func TestGenerateNoSimilar(t *testing.T) {
	o := DefaultOptions()
	o.NoSimilar = true
	for i := 0; i < 10; i++ {
		pw, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(pw, "1lIO0") {
			t.Errorf("carácter similar presente: %q", pw)
		}
	}
}

func TestGenerateTooShort(t *testing.T) {
	o := DefaultOptions()
	o.Length = 4
	if _, err := Generate(o); err == nil {
		t.Error("longitud 4 debería fallar")
	}
}

func TestGenerateLowercaseOnly(t *testing.T) {
	o := Options{Length: 16, Upper: false, Digits: false, Symbols: false, MinScore: 3, MinEntropy: 60}
	pw, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] < 'a' || pw[i] > 'z' {
			t.Errorf("carácter no minúscula: %q", pw)
		}
	}
}

func TestPassphrase(t *testing.T) {
	pw, err := GeneratePassphrase(4)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(pw, "-")
	if len(parts) != 4 {
		t.Errorf("frase-pase con %d palabras: %q", len(parts), pw)
	}
}

func TestRandomness(t *testing.T) {
	o := DefaultOptions()
	a, _ := Generate(o)
	b, _ := Generate(o)
	if a == b {
		t.Error("dos generaciones idénticas (¿RNG roto?)")
	}
}
