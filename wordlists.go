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

// wordlistPath returns cfg.wordlist if set, else writes the embedded brute list
// to a temp file and returns that path (caller removes it).
func wordlistPath(userPath, dir string) (path string, cleanup func()) {
	if userPath != "" {
		return userPath, func() {}
	}
	p := filepath.Join(dir, ".wordlist.tmp")
	os.WriteFile(p, []byte(defaultWordlist), 0o644)
	return p, func() { os.Remove(p) }
}

// permWordsPath is the same for the (small) permutation token list.
func permWordsPath(userPath, dir string) (path string, cleanup func()) {
	if userPath != "" {
		return userPath, func() {}
	}
	p := filepath.Join(dir, ".permwords.tmp")
	os.WriteFile(p, []byte(defaultPermWords), 0o644)
	return p, func() { os.Remove(p) }
}
