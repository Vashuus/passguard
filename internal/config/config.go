// Package config persists user preferences as JSON in ~/.config/passguard,
// mirroring how EngKey stores its configuration.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Vashuus/passguard/internal/generator"
)

// Config is the persisted user settings.
type Config struct {
	Language   string `json:"language"` // "es" | "en"
	DefaultLen int    `json:"default_len"`
	Symbols    bool   `json:"symbols"`
	Digits     bool   `json:"digits"`
	UpperCase  bool   `json:"upper_case"`
	Passphrase bool   `json:"passphrase"`
}

// Path returns the config file location.
func Path() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "passguard", "config.json")
}

// Load reads the config from disk, returning defaults when absent.
func Load() Config {
	c := Default()
	data, err := os.ReadFile(Path())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c)
	if c.Language == "" {
		c.Language = "es"
	}
	return c
}

// Default builds a config matching generator defaults.
func Default() Config {
	d := generator.DefaultOptions()
	return Config{
		Language:   "es",
		DefaultLen: d.Length,
		Symbols:    d.Symbols,
		Digits:     d.Digits,
		UpperCase:  d.Upper,
	}
}

// Save persists the config to disk.
func (c Config) Save() error {
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
