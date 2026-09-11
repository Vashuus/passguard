package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	c := Config{Language: "es", DefaultLen: 24, Symbols: false, Digits: true, UpperCase: true}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	got := Load()
	if got != c {
		t.Errorf("roundtrip failed: %+v != %+v", got, c)
	}
	if filepath.Base(Path()) != "config.json" {
		t.Errorf("ruta inesperada: %s", Path())
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	c := Load()
	if c.Language != "es" {
		t.Errorf("language por defecto = %q", c.Language)
	}
	if c.DefaultLen == 0 {
		t.Error("default_len no puede ser 0")
	}
}

func TestConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	c := Default()
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permisos = %v, esperado 0600", info.Mode().Perm())
	}
}
