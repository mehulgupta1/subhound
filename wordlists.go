package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed words/subdomains.txt
var defaultWordlist string

//go:embed words/perm-words.txt
var defaultPermWords string

//go:embed words/resolvers.txt
var defaultResolvers string

// subhoundConfigPath is subhound's OWN key store (~/.subhound/config.yaml), kept
// separate from subfinder's provider-config.yaml so subhound never edits subfinder's
// official config. Holds tokens only for subhound's own tools: github-subdomains
// (GitHub token) and asnmap/-asn (Chaos/PDCP key).
func subhoundConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".subhound", "config.yaml")
}

// readSubhoundConfig parses the simple `name: value` lines into a map (empty if none).
func readSubhoundConfig() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(subhoundConfigPath())
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if i := strings.Index(ln, ":"); i > 0 {
			m[strings.TrimSpace(ln[:i])] = strings.TrimSpace(ln[i+1:])
		}
	}
	return m
}

// subhoundFile returns ~/.subhound/<name> if it exists and is non-empty, else "".
func subhoundFile(name string) string {
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".subhound", name)
	if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
		return p
	}
	return ""
}

// wordlistPath returns the brute wordlist: user -w, else the big downloaded
// Assetnote list (~/.subhound/dns-wordlist.txt from -setup), else the embedded
// fallback written to a temp file.
func wordlistPath(userPath, dir string) (path string, cleanup func()) {
	if userPath != "" {
		return userPath, func() {}
	}
	if p := subhoundFile("dns-wordlist.txt"); p != "" {
		return p, func() {}
	}
	p := filepath.Join(dir, ".wordlist.tmp")
	os.WriteFile(p, []byte(defaultWordlist), 0o644)
	return p, func() { os.Remove(p) }
}

// permWordsPath is the same for the permutation token list: user -pw, else the
// downloaded six2dez list, else the embedded fallback.
func permWordsPath(userPath, dir string) (path string, cleanup func()) {
	if userPath != "" {
		return userPath, func() {}
	}
	if p := subhoundFile("perm-words.txt"); p != "" {
		return p, func() {}
	}
	p := filepath.Join(dir, ".permwords.tmp")
	os.WriteFile(p, []byte(defaultPermWords), 0o644)
	return p, func() { os.Remove(p) }
}
