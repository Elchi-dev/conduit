package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// profile is where one daemon is and the key to use there.
type profile struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

// config is ~/.config/conduit/config.json (mode 0600: it holds keys).
type config struct {
	Default  string             `json:"default"`
	Profiles map[string]profile `json:"profiles"`
}

// configPath honours CONDUIT_CONFIG, then XDG_CONFIG_HOME, then the OS
// default (%AppData% on Windows, ~/.config elsewhere).
func configPath() (string, error) {
	if p := os.Getenv("CONDUIT_CONFIG"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		if runtime.GOOS == "windows" {
			d, err := os.UserConfigDir()
			if err != nil {
				return "", err
			}
			dir = d
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(dir, "conduit", "config.json"), nil
}

func loadConfig() (config, error) {
	c := config{Profiles: map[string]profile{}}
	p, err := configPath()
	if err != nil {
		return c, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s is damaged: %w", p, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]profile{}
	}
	return c, nil
}

func saveConfig(c config) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}
