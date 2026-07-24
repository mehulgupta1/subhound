package main

// Step 2 — setup / auto-installer (Linux & macOS only).
// `subhound -setup` ensures Go exists, then installs each recon tool it calls by
// name. Idempotent (only installs what's missing), fail-soft (one optional tool
// failing never aborts the rest). Findomain is a release zip; the rest go install.

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// runConfig interactively stores API keys where the tools read them:
// subfinder's provider-config.yaml, plus hints for the env-var-based tools.
func runConfig() int {
	home, _ := os.UserHomeDir()
	cfgDir := filepath.Join(home, ".config", "subfinder")
	path := filepath.Join(cfgDir, "provider-config.yaml")

	// Load whatever's already saved so we MERGE (never wipe) — the old version
	// overwrote the file, so leaving a prompt blank silently deleted that key.
	cfg := parseProviderConfig(path)

	r := bufio.NewReader(os.Stdin)
	// ask shows the saved value (masked) and treats blank as "keep it". Only a
	// non-blank entry replaces. Returns the value to store for this provider.
	ask := func(provider, label string) []string {
		cur := cfg[provider]
		hint := "not set"
		if len(cur) == 1 {
			hint = "saved: " + mask(cur[0]) + " — Enter to keep"
		} else if len(cur) > 1 {
			hint = fmt.Sprintf("saved: %d keys — Enter to keep", len(cur))
		}
		fmt.Fprintf(os.Stderr, "  %-26s [%s]: ", label, hint)
		s, _ := r.ReadString('\n')
		if s = strings.TrimSpace(s); s == "" {
			return cur // keep existing
		}
		var vals []string
		for _, v := range strings.Split(s, ",") {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, v)
			}
		}
		return vals
	}
	fmt.Fprintln(os.Stderr, "[*] SubHound config — Enter keeps the saved value, or type a new one to replace")
	cfg["chaos"] = ask("chaos", "Chaos / PDCP key")
	cfg["github"] = ask("github", "GitHub token(s) — comma-separated")
	cfg["securitytrails"] = ask("securitytrails", "SecurityTrails key")
	cfg["virustotal"] = ask("virustotal", "VirusTotal key")

	// Render the merged config back (providers we didn't prompt for are preserved).
	var b strings.Builder
	for _, name := range sortedProviders(cfg) {
		vals := cfg[name]
		if len(vals) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s:\n", name)
		for _, v := range vals {
			fmt.Fprintf(&b, "  - %s\n", v)
		}
	}

	os.MkdirAll(cfgDir, 0o755)
	if b.Len() > 0 {
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot write %s: %v\n", path, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "[✓] wrote %s\n", path)
	} else {
		fmt.Fprintln(os.Stderr, "[*] no keys set — nothing written")
		return 0
	}
	chaos, github := first(cfg["chaos"]), strings.Join(cfg["github"], ",")

	// env-var-based tools need exports (persist them in your shell rc)
	fmt.Fprintln(os.Stderr, "\n[*] also add these to your shell (~/.bashrc or ~/.zshrc):")
	if github != "" {
		fmt.Fprintf(os.Stderr, "      export GITHUB_TOKEN=%s\n", github)
	}
	if chaos != "" {
		fmt.Fprintf(os.Stderr, "      export PDCP_API_KEY=%s   # enables ASN (asnmap)\n", chaos)
	}
	return 0
}

// parseProviderConfig reads subfinder's provider-config.yaml into provider->values.
// The format is simple enough (`name:` then `  - value` lines) to parse by hand,
// avoiding a YAML dependency. Missing file → empty map (fresh setup).
func parseProviderConfig(path string) map[string][]string {
	cfg := map[string][]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	cur := ""
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
		case strings.HasPrefix(t, "- "):
			if cur != "" {
				cfg[cur] = append(cfg[cur], strings.TrimSpace(t[2:]))
			}
		case strings.HasSuffix(t, ":"):
			cur = strings.TrimSuffix(t, ":")
			if _, ok := cfg[cur]; !ok {
				cfg[cur] = nil
			}
		}
	}
	return cfg
}

// mask shows a key's shape without printing it in full: 3527…4178.
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func sortedProviders(m map[string][]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

type tool struct {
	cmd      string // command name the pipeline calls
	pkg      string // `go install` path
	required bool
}

var tools = []tool{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", true},
	{"anew", "github.com/tomnomnom/anew@latest", true},
	{"asnmap", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", true},
	{"mapcidr", "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", true},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest", false},
	{"alterx", "github.com/projectdiscovery/alterx/cmd/alterx@latest", false},
	{"github-subdomains", "github.com/gwen001/github-subdomains@latest", false},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", false},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest", false},
	{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", false},
}

// requiredTools is the minimal set the pipeline needs to run at all.
func requiredCmds() []string {
	var r []string
	for _, t := range tools {
		if t.required {
			r = append(r, t.cmd)
		}
	}
	return r
}

// runSetup is the entry for `-setup`. Installs Go + tools, reports a summary.
func runSetup() int {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Fprintf(os.Stderr, "[!] SubHound supports Linux and macOS only (got %s)\n", runtime.GOOS)
		return 1
	}

	goExe, err := ensureGo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Go is required but could not be installed: %v\n", err)
		fmt.Fprintln(os.Stderr, "    install Go manually from https://go.dev/dl/ then re-run -setup")
		return 1
	}
	gobin := goBinDir(goExe)
	prependPath(gobin)
	prependPath(filepath.Dir(goExe))

	fmt.Fprintf(os.Stderr, "[*] Go: %s\n", goExe)
	fmt.Fprintf(os.Stderr, "[*] tools install to: %s\n\n", gobin)

	var failed []string
	for _, t := range tools {
		if p := resolveCmd(t.cmd, gobin); p != "" {
			fmt.Fprintf(os.Stderr, "  ✓ %-18s already installed\n", t.cmd)
			continue
		}
		fmt.Fprintf(os.Stderr, "  … installing %s\n", t.cmd)
		if err := goInstall(goExe, t.pkg); err != nil || resolveCmd(t.cmd, gobin) == "" {
			tag := "optional"
			if t.required {
				tag = "REQUIRED"
			}
			fmt.Fprintf(os.Stderr, "  ✗ %-18s failed (%s): %v\n", t.cmd, tag, err)
			failed = append(failed, t.cmd)
			continue
		}
		fmt.Fprintf(os.Stderr, "  ✓ %-18s installed\n", t.cmd)
	}

	// findomain — release zip, not go install (optional)
	if resolveCmd("findomain", gobin) == "" {
		fmt.Fprintf(os.Stderr, "  … installing findomain (release binary)\n")
		if err := installFindomain(gobin); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %-18s failed (optional): %v\n", "findomain", err)
			failed = append(failed, "findomain")
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %-18s installed\n", "findomain")
		}
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ %-18s already installed\n", "findomain")
	}

	// massdns — C tool built from source (the fast bulk resolver shuffledns drives)
	if resolveCmd("massdns", gobin) == "" {
		fmt.Fprintf(os.Stderr, "  … installing massdns (build from source)\n")
		if err := installMassdns(gobin); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %-18s failed (optional): %v\n", "massdns", err)
			failed = append(failed, "massdns")
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %-18s installed\n", "massdns")
		}
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ %-18s already installed\n", "massdns")
	}

	// Downloaded lists (all optional/fail-soft) into ~/.subhound/:
	//   resolvers = Trickest (fast massdns), dns-wordlist = Assetnote (9.5M brute),
	//   perm-words = six2dez (permutation tokens).
	if home, _ := os.UserHomeDir(); home != "" {
		sub := filepath.Join(home, ".subhound")
		os.MkdirAll(sub, 0o755)
		fetch := func(label, url, name string) {
			fmt.Fprintf(os.Stderr, "  … fetching %s\n", label)
			if err := download(url, filepath.Join(sub, name)); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %-18s download failed (optional): %v\n", label, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ %-18s ~/.subhound/%s\n", label, name)
			}
		}
		fetch("resolvers", "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", "resolvers.txt")
		fetch("dns-wordlist", "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt", "dns-wordlist.txt")
		fetch("perm-words", "https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/", "perm-words.txt")
	}

	fmt.Fprintln(os.Stderr)
	// abort only if a REQUIRED tool failed
	var reqFailed []string
	for _, f := range failed {
		for _, t := range tools {
			if t.cmd == f && t.required {
				reqFailed = append(reqFailed, f)
			}
		}
	}
	if len(reqFailed) > 0 {
		fmt.Fprintf(os.Stderr, "[!] setup incomplete — required tools failed: %s\n", strings.Join(reqFailed, ", "))
		return 1
	}

	writeMarker(gobin)
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "[✓] setup done (optional skipped: %s)\n", strings.Join(failed, ", "))
	} else {
		fmt.Fprintln(os.Stderr, "[✓] setup complete — all tools installed")
	}
	fmt.Fprintf(os.Stderr, "    NOTE: add %s to your PATH if not already:\n", gobin)
	fmt.Fprintf(os.Stderr, "      export PATH=\"$PATH:%s\"\n", gobin)
	return 0
}

// ensureGo returns a working go binary path, installing Go if missing.
func ensureGo() (string, error) {
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	if fileExists("/usr/local/go/bin/go") {
		return "/usr/local/go/bin/go", nil
	}
	fmt.Fprintln(os.Stderr, "[*] Go not found — installing via udhos/update-golang …")
	script := filepath.Join(os.TempDir(), "update-golang.sh")
	if err := download("https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh", script); err != nil {
		return "", fmt.Errorf("download installer: %w", err)
	}
	defer os.Remove(script)

	name, args := "bash", []string{script}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err == nil {
			name, args = "sudo", []string{"bash", script}
		}
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "SOURCE_ONLY=") // non-interactive
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		// update-golang can return non-zero yet still install; fall through to check
		fmt.Fprintf(os.Stderr, "[*] installer exited: %v (checking anyway)\n", err)
	}
	if fileExists("/usr/local/go/bin/go") {
		return "/usr/local/go/bin/go", nil
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("go still not found after install")
}

func goInstall(goExe, pkg string) error {
	cmd := exec.Command(goExe, "install", pkg)
	cmd.Env = append(os.Environ(), "GO111MODULE=on", "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func goBinDir(goExe string) string {
	if out, err := exec.Command(goExe, "env", "GOBIN").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s
		}
	}
	if out, err := exec.Command(goExe, "env", "GOPATH").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return filepath.Join(s, "bin")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "go", "bin")
}

// resolveCmd returns a path for cmd if it exists on PATH or in gobin, else "".
func resolveCmd(cmd, gobin string) string {
	if p, err := exec.LookPath(cmd); err == nil {
		return p
	}
	p := filepath.Join(gobin, cmd)
	if fileExists(p) {
		return p
	}
	return ""
}

// installFindomain downloads + extracts the right release binary for this OS/arch.
func installFindomain(gobin string) error {
	asset := findomainAsset()
	if asset == "" {
		return fmt.Errorf("no findomain asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	url := "https://github.com/findomain/findomain/releases/latest/download/" + asset
	zipPath := filepath.Join(os.TempDir(), asset)
	if err := download(url, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		return err
	}
	// extract the single `findomain` binary from the zip (no system unzip needed)
	return unzipBinary(zipPath, "findomain", filepath.Join(gobin, "findomain"))
}

// installMassdns builds massdns from source (git clone + make) into gobin — it's
// the fast bulk resolver shuffledns drives. Needs git, make, and a C compiler.
func installMassdns(gobin string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found")
	}
	if _, err := exec.LookPath("make"); err != nil {
		return fmt.Errorf("make not found")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		if _, e2 := exec.LookPath("cc"); e2 != nil {
			return fmt.Errorf("no C compiler (gcc/cc) found")
		}
	}
	tmp, err := os.MkdirTemp("", "massdns")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "massdns")
	clone := exec.Command("git", "clone", "--depth", "1", "https://github.com/blechschmidt/massdns.git", src)
	clone.Stdout, clone.Stderr = os.Stderr, os.Stderr
	if err := clone.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	mk := exec.Command("make")
	mk.Dir = src
	mk.Stdout, mk.Stderr = os.Stderr, os.Stderr
	if err := mk.Run(); err != nil {
		return fmt.Errorf("make: %w", err)
	}
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		return err
	}
	bin, err := os.ReadFile(filepath.Join(src, "bin", "massdns"))
	if err != nil {
		return fmt.Errorf("read built binary: %w", err)
	}
	return os.WriteFile(filepath.Join(gobin, "massdns"), bin, 0o755)
}

func findomainAsset() string {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return "findomain-linux.zip"
		case "arm64":
			return "findomain-aarch64.zip"
		case "386":
			return "findomain-linux-i386.zip"
		}
	case "darwin":
		switch runtime.GOARCH {
		case "arm64":
			return "findomain-osx-arm64.zip"
		case "amd64":
			return "findomain-osx-x86_64.zip"
		}
	}
	return ""
}

func writeMarker(gobin string) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".subhound")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, ".setup-done"), []byte(gobin+"\n"), 0o644)
}

// --- helpers ---

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func prependPath(dir string) {
	if dir == "" {
		return
	}
	cur := os.Getenv("PATH")
	if !strings.Contains(cur, dir) {
		os.Setenv("PATH", dir+string(os.PathListSeparator)+cur)
	}
}

func download(url, dst string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// unzipBinary extracts the entry whose base name == wantName into dstPath (chmod +x).
func unzipBinary(zipPath, wantName, dstPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) != wantName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, rc)
		return err
	}
	return fmt.Errorf("%s not found inside %s", wantName, zipPath)
}
