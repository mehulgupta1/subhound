package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed words/subdomains.txt
var defaultWordlist string

//go:embed words/perm-words.txt
var defaultPermWords string

//go:embed words/resolvers.txt
var defaultResolvers string

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
