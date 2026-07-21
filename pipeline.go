package main

// Step 3 — passive discovery + resolve + output, with per-source error surfacing
// (the no-false-zeros rule). Passive sources run in parallel; results merge/dedup
// in Go; dnsx resolves + strips wildcards.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// currentDir holds the active output dir so the interrupt handler can point the
// user at their partial results. Results are written incrementally after each
// stage, so on Ctrl-C the files already hold everything up to the current stage.
var currentDir atomic.Value // string

// installInterruptHandler flushes-by-pointing on SIGINT/SIGTERM: files are already
// on disk (incremental saves), so we just tell the user where they are and exit.
func installInterruptHandler() {
	currentDir.Store("")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		stopHeartbeat()
		if d, _ := currentDir.Load().(string); d != "" {
			fmt.Fprintf(os.Stderr, "\n[!] interrupted — partial results saved in %s/\n", d)
		} else {
			fmt.Fprintln(os.Stderr, "\n[!] interrupted")
		}
		os.Exit(130)
	}()
}

// ── live heartbeat ───────────────────────────────────────────────────────────
// Long stages (permutation, resolve, ASN) can churn for many minutes emitting no
// output, leaving you unsure whether it's working or hung. The heartbeat prints a
// spinner + current stage + elapsed time, refreshed a few times a second, so the
// scan visibly stays alive. Interactive terminals only — piped/-silent is a no-op
// (output stays clean for parsing).
var (
	hbMu      sync.Mutex   // serializes stderr writes between logf and the ticker
	hbStage   atomic.Value // string: current stage label
	hbStageAt atomic.Value // time.Time: when the current stage began
	hbCount   atomic.Int64 // live result counter for the current stage/sub-phase
	hbActive  bool
	hbStop    chan struct{}
)

// setStage labels the current stage, resets the live counter, and restarts the
// per-stage timer — so the heartbeat shows how long THIS stage has run (not the
// whole scan), which is what tells you if a stage is actually stuck.
func setStage(s string) {
	hbStage.Store(s)
	hbStageAt.Store(time.Now())
	hbCount.Store(0)
}

// hbBump increments the live counter — called per result line by runStream.
func hbBump() { hbCount.Add(1) }

func startHeartbeat(silent bool) {
	if silent || !isTerminal(os.Stderr) {
		return
	}
	hbActive = true
	hbStop = make(chan struct{})
	hbStage.Store("starting")
	hbStageAt.Store(time.Now())
	go func() {
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		start := time.Now()
		tick := time.NewTicker(150 * time.Millisecond)
		defer tick.Stop()
		var lastN int64  // count at the last rate sample
		lastT := start   // time of the last rate sample
		var rate float64 // current results/sec (rolling ~1s window)
		for i := 0; ; i++ {
			select {
			case <-hbStop:
				hbMu.Lock()
				fmt.Fprint(os.Stderr, "\r\033[K")
				hbMu.Unlock()
				return
			case <-tick.C:
				s, _ := hbStage.Load().(string)
				n := hbCount.Load()
				now := time.Now()
				if n < lastN { // counter reset (new stage) → restart the rate window
					lastN, lastT, rate = n, now, 0
				} else if dt := now.Sub(lastT); dt >= time.Second {
					rate = float64(n-lastN) / dt.Seconds()
					lastN, lastT = n, now
				}
				stageAt, _ := hbStageAt.Load().(time.Time)
				line := fmt.Sprintf("  %c %s… %s", frames[i%len(frames)], s, fmtElapsed(time.Since(stageAt)))
				if n > 0 {
					line += fmt.Sprintf(" · %s", commafy(n))
					if rate >= 1 {
						line += fmt.Sprintf(" · %s/s", commafy(int64(rate)))
					}
				}
				hbMu.Lock()
				fmt.Fprintf(os.Stderr, "\r\033[K%s", line)
				hbMu.Unlock()
			}
		}
	}()
}

func stopHeartbeat() {
	if hbActive {
		close(hbStop)
		hbActive = false
	}
}

func fmtElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	if m := int(d.Minutes()); m > 0 {
		return fmt.Sprintf("%dm%02ds", m, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// commafy renders n with thousands separators (12345 → "12,345").
func commafy(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		b.WriteByte(',')
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// per-source hard wall-clock cap: a stuck source can't stall the phase.
// On timeout we keep whatever it already printed (partial results are fine).
// Fast default, but generous for -all (thorough mode legitimately takes longer).
func passiveTimeout(cfg config) time.Duration {
	// Must exceed subfinder's own -max-time (see subfinderArgs) so subfinder
	// self-terminates gracefully with partial results instead of being SIGKILLed
	// at this wall — a SIGKILL would read as a hard error and drop the source.
	if cfg.all {
		return 270 * time.Second // subfinder -max-time 4m (240s) + margin
	}
	return 90 * time.Second // subfinder -max-time 1m (60s) + margin
}

// srcResult is one passive source's outcome — captured so failures are visible.
type srcResult struct {
	source string
	names  []string
	err    error
	stderr string
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// runPipeline is the real per-domain entry (replaces the Step-1 skeleton).
func runPipeline(cfg config, domain string) int {
	setupRunPath()

	// "not set up yet" detection — check the tools the active stages need.
	if miss := missingNeeded(cfg); len(miss) > 0 {
		fmt.Fprintf(os.Stderr, "[!] missing tool(s): %s\n", strings.Join(miss, ", "))
		fmt.Fprintln(os.Stderr, "    run:  subhound -setup")
		return 1
	}

	dir := cfg.outDir
	if dir == "" {
		dir = fmt.Sprintf("subhound-%s-%s", domain, timestamp())
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot create output dir %s: %v\n", dir, err)
		return 1
	}
	currentDir.Store(dir) // for the interrupt handler

	// default to the bundled trusted resolvers unless the user supplied their own
	if cfg.resolvers == "" {
		rp := filepath.Join(dir, ".resolvers.txt")
		if os.WriteFile(rp, []byte(defaultResolvers), 0o644) == nil {
			cfg.resolvers = rp
		}
	}

	logf(cfg.silent, "%s[*]%s target : %s", bold, reset, domain)
	logf(cfg.silent, "%s[*]%s modes  : %s", bold, reset, strings.Join(modeList(cfg), ", "))
	logf(cfg.silent, "%s[*]%s output : %s/", bold, reset, dir)
	logf(cfg.silent, "")

	startHeartbeat(cfg.silent)
	defer stopHeartbeat()

	excl := loadExcluder(cfg.exclude)
	set := map[string]struct{}{}
	resolved := map[string][]string{}
	sourcesErrored := 0

	// save writes current results to disk — called after each stage so Ctrl-C
	// (or a crash) always leaves the latest completed results on disk.
	save := func() {
		writeLines(filepath.Join(dir, "all-subdomains.txt"), sortedKeys(set))
		writeResolved(dir, resolved)
	}

	// ---- PASSIVE ----
	if cfg.passive {
		setStage("passive sources")
		logf(cfg.silent, "[1] PASSIVE")
		for _, r := range passiveStage(cfg, domain) {
			// Only a HARD failure (error AND no output) counts as errored — a source
			// that timed out but returned partial data is still usable.
			if r.err != nil && len(r.names) == 0 {
				sourcesErrored++
				logf(cfg.silent, "  %s✗%s %-16s ERROR: %s", red(), reset, r.source, firstLine(r.stderr, r.err))
				continue
			}
			kept := 0
			for _, n := range r.names {
				if n = normalize(n, domain); n != "" && !excl.match(n) {
					if _, ok := set[n]; !ok {
						set[n] = struct{}{}
					}
					kept++
				}
			}
			note := ""
			if r.err != nil {
				note = " (timed out, partial)"
			}
			logf(cfg.silent, "  %s✓%s %-16s %d%s", green(), reset, r.source, kept, note)
		}
		logf(cfg.silent, "  → %d unique names", len(set))
		logf(cfg.silent, "")
		save()
	}

	// ---- BRUTEFORCE ----
	if cfg.brute {
		setStage("bruteforce")
		logf(cfg.silent, "[b] BRUTEFORCE")
		added := addNames(set, bruteStage(cfg, domain, dir), domain, excl)
		logf(cfg.silent, "  → %d new resolving names", added)
		logf(cfg.silent, "")
		save()
	}

	// ---- PERMUTATION ---- (iterative alterx + resolve feedback loop)
	if cfg.perm {
		setStage("permutation")
		logf(cfg.silent, "[p] PERMUTATE (iterative)")
		added := addNames(set, permStage(cfg, domain, set, excl, dir), domain, excl)
		logf(cfg.silent, "  → %d new resolving names (total)", added)
		logf(cfg.silent, "")
		save()
	}

	// ---- ASN SWEEP ---- (owned IP space → reverse DNS)
	if cfg.asn {
		setStage("ASN sweep")
		logf(cfg.silent, "[a] ASN SWEEP")
		added := addNames(set, asnStage(cfg, domain, dir), domain, excl)
		logf(cfg.silent, "  → %d new names (reverse-DNS)", added)
		logf(cfg.silent, "")
		save()
	}

	// no-false-zeros guard (based on discovery)
	if len(set) == 0 && sourcesErrored > 0 {
		fmt.Fprintf(os.Stderr, "[!] 0 subdomains found — BUT %d source(s) errored above.\n", sourcesErrored)
		fmt.Fprintln(os.Stderr, "    This is likely a FAILURE, not an empty result. Fix the errors / check keys and retry.")
		return 2
	}

	// ---- RESOLVE ----
	setStage(fmt.Sprintf("resolving %s names", commafy(int64(len(set)))))
	logf(cfg.silent, "[2] RESOLVE + wildcard filter")
	for h, ips := range resolveNames(cfg, domain, sortedKeys(set), dir) {
		resolved[h] = ips
	}
	logf(cfg.silent, "  → %d live subdomains", len(resolved))
	logf(cfg.silent, "")
	save()

	// ---- TLS HARVEST ---- (after resolve; reads certs from live hosts)
	if cfg.tls {
		setStage("TLS harvest")
		logf(cfg.silent, "[t] TLS HARVEST")
		n := harvestInto(cfg, domain, set, excl, resolved, dir, tlsStage(cfg, domain, sortedKeys(resolved), dir))
		logf(cfg.silent, "  → %d new names from certs", n)
		logf(cfg.silent, "")
		save()
	}

	// ---- VHOST BRUTE ---- (hidden hosts on a shared IP)
	if cfg.vhost {
		setStage("vhost brute")
		logf(cfg.silent, "[v] VHOST BRUTE")
		n := harvestInto(cfg, domain, set, excl, resolved, dir, vhostStage(cfg, domain, resolved, dir))
		logf(cfg.silent, "  → %d vhosts found", n)
		logf(cfg.silent, "")
		save()
	}

	all := sortedKeys(set)

	// ---- PROBE ----
	aliveCount := 0
	if cfg.probe {
		setStage(fmt.Sprintf("probing %s hosts", commafy(int64(len(resolved)))))
		logf(cfg.silent, "[3] PROBE (httpx)")
		aliveCount = probeStage(cfg, sortedKeys(resolved), dir)
		logf(cfg.silent, "  → %d alive hosts", aliveCount)
		logf(cfg.silent, "")
	}

	// summary
	stopHeartbeat()
	logf(cfg.silent, "%s[✓]%s done — all:%d  resolved:%d  alive:%d", bold, reset, len(all), len(resolved), aliveCount)
	logf(cfg.silent, "    results in %s/", dir)

	// 0 results is almost always a mode issue, not a real "nothing exists" — say why
	// so an empty scan never looks like a silent failure.
	if len(all) == 0 {
		if !cfg.passive {
			logf(cfg.silent, "  %s⚠%s  0 subdomains — passive is OFF (-no-passive), which is the main source. For a normal scan:  subhound -d %s", red(), reset, domain)
		} else {
			logf(cfg.silent, "  %s⚠%s  0 subdomains — the enabled stages found nothing. Try more sources:  subhound -d %s -all -brute", red(), reset, domain)
		}
	}

	// silent mode: bare subdomain list to stdout (pipe-friendly)
	if cfg.silent {
		src := all
		if len(resolved) > 0 {
			src = sortedKeys(resolved)
		}
		for _, n := range src {
			fmt.Println(n)
		}
	}
	return 0
}

// passiveStage runs the passive sources concurrently (they use different backends,
// so parallel is safe — see controlled-parallelism rule).
func passiveStage(cfg config, domain string) []srcResult {
	type job struct {
		name string
		bin  string
		args []string
		skip bool
	}
	jobs := []job{
		{name: "subfinder", bin: "subfinder", args: subfinderArgs(cfg, domain)},
		{name: "assetfinder", bin: "assetfinder", args: []string{"--subs-only", domain}},
		{name: "findomain", bin: "findomain", args: []string{"-t", domain, "-q"}},
	}
	// github-subdomains if a token is available — env var OR the one saved via
	// `subhound -config` (so a pasted -config token works without exporting it).
	if tok := githubToken(); tok != "" {
		jobs = append(jobs, job{name: "github-subdomains", bin: "github-subdomains", args: []string{"-d", domain, "-t", tok}})
	}

	results := make([]srcResult, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		// skip optional sources whose binary isn't installed (not an error)
		if _, err := exec.LookPath(j.bin); err != nil {
			results[i] = srcResult{source: j.name, err: fmt.Errorf("not installed (optional)"), stderr: "skipped"}
			continue
		}
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			out, serr, err := runToolCtx(passiveTimeout(cfg), j.bin, j.args...)
			results[i] = srcResult{source: j.name, names: out, err: err, stderr: serr}
		}(i, j)
	}
	wg.Wait()
	return results
}

// subfinderKey reads a provider's key from subfinder's provider-config.yaml —
// where `subhound -config` saves keys — so a key pasted into -config "just works"
// for our own tools too. Returns "" if not found.
func subfinderKey(provider string) string {
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(filepath.Join(home, ".config", "subfinder", "provider-config.yaml"))
	if err != nil {
		return ""
	}
	in := false
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case t == provider+":":
			in = true
		case in && strings.HasPrefix(t, "- "):
			return strings.TrimSpace(t[2:])
		case in && t != "" && !strings.HasPrefix(t, "-"):
			in = false // moved on to the next provider block
		}
	}
	return ""
}

// githubToken: GITHUB_TOKEN env, else the token saved via `subhound -config`.
func githubToken() string {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t
	}
	return subfinderKey("github")
}

// pdcpKey: PDCP_API_KEY env (asnmap reads this), else the Chaos/PDCP key saved
// via `subhound -config`.
func pdcpKey() string {
	if t := strings.TrimSpace(os.Getenv("PDCP_API_KEY")); t != "" {
		return t
	}
	return subfinderKey("chaos")
}

func subfinderArgs(cfg config, domain string) []string {
	// Bound subfinder so it returns (with partial results) BEFORE passiveTimeout's
	// wall kills it: -timeout = per-source seconds, -max-time = overall minutes.
	// Without this, a slow keyless source drags the run past the wall → SIGKILL →
	// the whole source reads as an error and its results are lost.
	timeout, maxTime := "15", "1"
	if cfg.all {
		timeout, maxTime = "30", "4" // -all queries more sources; give them longer
	}
	a := []string{"-d", domain, "-silent", "-timeout", timeout, "-max-time", maxTime}
	if cfg.all {
		a = append(a, "-all")
	}
	if cfg.threads > 0 {
		a = append(a, "-t", itoa(cfg.threads))
	}
	return a
}

// bruteStage runs dnsx bruteforce with the wordlist against the apex domain.
// dnsx only emits names that resolve, and -wd strips wildcard noise.
func bruteStage(cfg config, domain, dir string) []string {
	wl, cleanup := wordlistPath(cfg.wordlist, dir)
	defer cleanup()

	args := []string{"-d", domain, "-w", wl, "-silent", "-nc", "-wd", domain}
	if cfg.resolvers != "" {
		args = append(args, "-r", cfg.resolvers)
	}
	if cfg.threads > 0 {
		args = append(args, "-t", itoa(cfg.threads))
	}
	lines, serr, err := runTool("dnsx", args...)
	if err != nil && len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "  %s✗%s dnsx brute failed: %s\n", red(), reset, firstLine(serr, err))
		return nil
	}
	var out []string
	for _, ln := range lines {
		if h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); h != "" {
			// dnsx brute may emit "host" or "host [ip]"; take the host token
			if i := strings.IndexAny(h, " \t"); i > 0 {
				h = h[:i]
			}
			out = append(out, h)
		}
	}
	return out
}

// permExplosionCap: per-iteration candidate ceiling (guard against blow-ups).
const permExplosionCap = 5_000_000

// maxPermIters caps the feedback loop so it always terminates. 3 rounds captures
// nearly all finds — rounds 4-5 almost never add anything but cost a lot.
const maxPermIters = 3

// permStage — ITERATIVE permutation (alterx generate → dnsx resolve → feed the
// newly-found names back in → repeat until nothing new). This is how deep names
// like dev.legacy.api.internal.example.com surface: each round's discoveries
// become seeds for the next. seen (from set) prevents re-reporting known names.
func permStage(cfg config, domain string, set map[string]struct{}, excl *excluder, dir string) []string {
	if len(set) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(set))
	for k := range set {
		seen[k] = struct{}{}
	}
	seeds := sortedKeys(set)
	var allNew []string

	for iter := 1; iter <= maxPermIters; iter++ {
		setStage(fmt.Sprintf("permutation r%d · generating", iter))
		cands := alterxGen(cfg, seeds, dir)
		if len(cands) == 0 {
			break
		}
		if len(cands) > permExplosionCap {
			fmt.Fprintf(os.Stderr, "  %s⚠%s  iter %d: %d candidates exceeds cap %d — stopping loop\n",
				red(), reset, iter, len(cands), permExplosionCap)
			break
		}
		setStage(fmt.Sprintf("permutation r%d · resolving %s guesses", iter, commafy(int64(len(cands)))))
		var fresh []string
		for _, n := range shuffledResolve(cfg, domain, cands, dir) {
			if n = normalize(n, domain); n != "" && !excl.match(n) {
				if _, ok := seen[n]; !ok {
					seen[n] = struct{}{}
					fresh = append(fresh, n)
					allNew = append(allNew, n)
				}
			}
		}
		logf(cfg.silent, "  iter %d: %d candidates → %d new", iter, len(cands), len(fresh))
		if len(fresh) == 0 {
			break // loop stabilized — nothing new discovered
		}
		seeds = fresh // feed ONLY the newly-found names back in
	}
	return allNew
}

// alterxGen runs alterx over the seeds to produce mutation candidates.
func alterxGen(cfg config, seeds []string, dir string) []string {
	seedFile := filepath.Join(dir, ".perm-seeds.tmp")
	writeLines(seedFile, seeds)
	defer os.Remove(seedFile)
	// -limit caps generation at the source so we never resolve an unbounded
	// explosion of guesses (the perm-cap; 0 = unlimited for deep scans).
	args := []string{"-l", seedFile, "-silent"}
	if cfg.permLimit > 0 {
		args = append(args, "-limit", itoa(cfg.permLimit))
	}
	out, serr, err := runTool("alterx", args...)
	if err != nil && len(out) == 0 {
		fmt.Fprintf(os.Stderr, "  %s✗%s alterx failed: %s\n", red(), reset, firstLine(serr, err))
		return nil
	}
	var cands []string
	for _, ln := range out {
		if h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); h != "" {
			cands = append(cands, h)
		}
	}
	return cands
}

// dnsxResolveList resolves a candidate list (wildcard-filtered), returning the
// hostnames that resolve.
func dnsxResolveList(cfg config, domain string, names []string, dir string) []string {
	candFile := filepath.Join(dir, ".perm-cands.tmp")
	writeLines(candFile, names)
	defer os.Remove(candFile)
	args := []string{"-l", candFile, "-silent", "-nc", "-wd", domain}
	if cfg.resolvers != "" {
		args = append(args, "-r", cfg.resolvers)
	}
	if cfg.threads > 0 {
		args = append(args, "-t", itoa(cfg.threads))
	}
	lines, _, _ := runTool("dnsx", args...)
	var out []string
	for _, ln := range lines {
		if h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); h != "" {
			if i := strings.IndexAny(h, " \t"); i > 0 {
				h = h[:i]
			}
			out = append(out, h)
		}
	}
	return out
}

// hasTool reports whether a binary is on PATH.
func hasTool(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// bigResolvers returns the LARGE resolver list (Trickest, ~/.subhound/resolvers.txt)
// for the fast massdns pass; falls back to the trusted/bundled list if absent.
func bigResolvers(cfg config) string {
	home, _ := os.UserHomeDir()
	big := filepath.Join(home, ".subhound", "resolvers.txt")
	if fileExists(big) {
		return big
	}
	return cfg.resolvers
}

// shuffledResolve resolves a big candidate list FAST via shuffledns (massdns):
// the large list (-r) for raw speed + the trusted list (-tr) to verify hits and
// kill false positives, with shuffledns's own wildcard filtering. Falls back to
// dnsx if shuffledns/massdns aren't installed, so nothing breaks.
func shuffledResolve(cfg config, domain string, names []string, dir string) []string {
	if !hasTool("shuffledns") || !hasTool("massdns") {
		return dnsxResolveList(cfg, domain, names, dir) // fallback: dnsx
	}
	listFile := filepath.Join(dir, ".sh-cands.tmp")
	writeLines(listFile, names)
	defer os.Remove(listFile)
	// No -t: shuffledns defaults to 10000 massdns resolves; forcing dnsx-scale
	// threads (100) would cripple it. -r big list, -tr trusted verify.
	args := []string{"-d", domain, "-l", listFile, "-mode", "resolve", "-silent",
		"-r", bigResolvers(cfg), "-tr", cfg.resolvers}
	out, serr, err := runTool("shuffledns", args...)
	if err != nil && len(out) == 0 {
		fmt.Fprintf(os.Stderr, "  %s⚠%s shuffledns failed (%s) — using dnsx\n", red(), reset, firstLine(serr, err))
		return dnsxResolveList(cfg, domain, names, dir)
	}
	var res []string
	for _, ln := range out {
		if h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); h != "" {
			res = append(res, h)
		}
	}
	return res
}

// addNames normalizes/scope-filters/excludes names into set, returns count added.
func addNames(set map[string]struct{}, names []string, domain string, excl *excluder) int {
	added := 0
	for _, n := range names {
		if n = normalize(n, domain); n != "" && !excl.match(n) {
			if _, ok := set[n]; !ok {
				set[n] = struct{}{}
				added++
			}
		}
	}
	return added
}

// writeResolved writes the resolved map to resolved.txt ("host ip1,ip2").
func writeResolved(dir string, resolved map[string][]string) {
	var lo []string
	for host, ips := range resolved {
		if len(ips) > 0 {
			lo = append(lo, host+" "+strings.Join(ips, ","))
		} else {
			lo = append(lo, host)
		}
	}
	sort.Strings(lo)
	writeLines(filepath.Join(dir, "resolved.txt"), lo)
}

// resolveNames resolves names with dnsx (+wildcard filter) and returns host→IPs.
// Does NOT write files (caller writes once, after TLS may add more).
func resolveNames(cfg config, domain string, names []string, dir string) map[string][]string {
	out := map[string][]string{}
	if len(names) == 0 {
		return out
	}
	extra := []string{"-nc"}
	if cfg.resolvers != "" {
		extra = append(extra, "-r", cfg.resolvers)
	}
	if cfg.threads > 0 {
		extra = append(extra, "-t", itoa(cfg.threads))
	}

	// Pass 1 — resolve + WILDCARD FILTER (-wd suppresses IP output, so hostnames only).
	tmp := filepath.Join(dir, ".all.tmp")
	writeLines(tmp, names)
	defer os.Remove(tmp)
	p1, serr, err := runTool("dnsx", append([]string{"-l", tmp, "-silent", "-wd", domain}, extra...)...)
	if err != nil && len(p1) == 0 {
		fmt.Fprintf(os.Stderr, "  %s✗%s dnsx resolve failed: %s\n", red(), reset, firstLine(serr, err))
	}
	var filtered []string
	for _, ln := range p1 {
		if h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); h != "" {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) == 0 {
		return out
	}

	// Pass 2 — fetch IPs for the wildcard-filtered survivors (small set, fast).
	tmp2 := filepath.Join(dir, ".resolved.tmp")
	writeLines(tmp2, filtered)
	defer os.Remove(tmp2)
	p2, _, _ := runTool("dnsx", append([]string{"-l", tmp2, "-a", "-resp", "-silent"}, extra...)...)

	seen := map[string]map[string]struct{}{}
	for _, h := range filtered {
		seen[h] = map[string]struct{}{} // ensure survivors appear even if IP parse misses
	}
	for _, ln := range p2 {
		host, ip := parseDnsxResp(ln)
		if host == "" {
			continue
		}
		if seen[host] == nil {
			seen[host] = map[string]struct{}{}
		}
		if ip != "" {
			seen[host][ip] = struct{}{}
		}
	}
	for host, ips := range seen {
		out[host] = sortedKeys(ips)
	}
	return out
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var ipRe = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+`)
var cidrRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)

// asnIPCap limits reverse-DNS work — a big ASN can expand to hundreds of
// thousands of IPs; scanning all is too slow, so we cap + warn. (CDN ranges like
// Cloudflare are huge AND unproductive since the IPs aren't owned by the target.)
const asnIPCap = 16384

// asnStage: domain → ASN CIDRs (asnmap) → IPs (mapcidr) → reverse-DNS (dnsx -ptr),
// filtered back to the target. asnmap needs a ProjectDiscovery API key; if missing
// it's surfaced clearly (never a silent false-zero).
func asnStage(cfg config, domain, dir string) []string {
	// asnmap needs a PDCP key. Use PDCP_API_KEY, else the Chaos/PDCP key saved via
	// `subhound -config`. With NO key asnmap just hangs — so skip fast instead of
	// burning the 60s timeout below (that hang was the real "ASN takes forever" bug).
	key := pdcpKey()
	if key == "" {
		fmt.Fprintf(os.Stderr, "  %s⚠%s  ASN needs a ProjectDiscovery API key. Set PDCP_API_KEY (free at cloud.projectdiscovery.io) or run `subhound -config` — skipping ASN.\n", red(), reset)
		return nil
	}
	os.Setenv("PDCP_API_KEY", key) // ensure the asnmap subprocess sees it

	// asnmap can still hang on network/API/rate-limit with no output, so cap it at
	// 60s (it normally returns in seconds) as a safety net.
	actx, acancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer acancel()
	outLines, serr, _ := runStream(actx, true, "asnmap", "-d", domain, "-silent")
	var cidrs []string
	for _, ln := range outLines {
		if c := ansiRe.ReplaceAllString(strings.TrimSpace(ln), ""); cidrRe.MatchString(c) {
			cidrs = append(cidrs, c)
		}
	}
	if len(cidrs) == 0 {
		blob := strings.ToLower(strings.Join(outLines, " ") + " " + serr)
		if strings.Contains(blob, "api key") || strings.Contains(blob, "pdcp") {
			fmt.Fprintf(os.Stderr, "  %s⚠%s  ASN needs a ProjectDiscovery API key. Set PDCP_API_KEY (free at cloud.projectdiscovery.io), or run `subhound -config`, then retry.\n", red(), reset)
		} else {
			logf(cfg.silent, "  no ASN ranges found for this target")
		}
		return nil
	}
	logf(cfg.silent, "  %d CIDR range(s)", len(cidrs))

	cidrFile := filepath.Join(dir, ".cidrs.tmp")
	writeLines(cidrFile, cidrs)
	defer os.Remove(cidrFile)
	ipLines, _, _ := runTool("mapcidr", "-cl", cidrFile, "-silent")
	var ips []string
	for _, ln := range ipLines {
		if ip := ipRe.FindString(ln); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) > asnIPCap {
		fmt.Fprintf(os.Stderr, "  %s⚠%s  %d IPs in ASN space — capping reverse-DNS to first %d\n", red(), reset, len(ips), asnIPCap)
		ips = ips[:asnIPCap]
	}
	logf(cfg.silent, "  reverse-DNS on %d IPs", len(ips))

	ipFile := filepath.Join(dir, ".ips.tmp")
	writeLines(ipFile, ips)
	defer os.Remove(ipFile)
	// reverse-DNS is bounded internal work — push concurrency + rate high, and use
	// the resolver list so we don't hammer a single resolver.
	t := cfg.threads
	if t < 200 {
		t = 200
	}
	pargs := []string{"-l", ipFile, "-ptr", "-resp-only", "-silent", "-nc", "-t", itoa(t), "-rl", "2000"}
	if cfg.resolvers != "" {
		pargs = append(pargs, "-r", cfg.resolvers)
	}
	ptr, _, _ := runToolCtx(120*time.Second, "dnsx", pargs...)
	var out []string
	for _, ln := range ptr {
		h := ansiRe.ReplaceAllString(strings.TrimSpace(ln), "")
		if h != "" {
			out = append(out, h) // scope-filtered by addNames() against the domain
		}
	}
	return out
}

// harvestInto adds new in-scope names to set, resolves the fresh ones, and merges
// them into resolved. Returns how many were new. Shared by TLS + VHOST stages.
func harvestInto(cfg config, domain string, set map[string]struct{}, excl *excluder, resolved map[string][]string, dir string, names []string) int {
	var fresh []string
	for _, n := range names {
		if n = normalize(n, domain); n != "" && !excl.match(n) {
			if _, ok := set[n]; !ok {
				set[n] = struct{}{}
				fresh = append(fresh, n)
			}
		}
	}
	if len(fresh) > 0 {
		for h, ips := range resolveNames(cfg, domain, fresh, dir) {
			resolved[h] = ips
		}
	}
	return len(fresh)
}

// vhostStage bruteforces virtual hosts against a target IP with Host: FUZZ.domain.
// Best against a raw origin server; on CDN/shared IPs results are limited.
func vhostStage(cfg config, domain string, resolved map[string][]string, dir string) []string {
	ip := ""
	if ips, ok := resolved[domain]; ok && len(ips) > 0 {
		ip = ips[0]
	} else {
		for _, ips := range resolved {
			if len(ips) > 0 {
				ip = ips[0]
				break
			}
		}
	}
	// solo-mode (-no-passive): nothing resolved yet — resolve the apex to get an IP.
	if ip == "" {
		for _, ips := range resolveNames(cfg, domain, []string{domain}, dir) {
			if len(ips) > 0 {
				ip = ips[0]
				break
			}
		}
	}
	if ip == "" {
		logf(cfg.silent, "  no resolved IP to vhost against")
		return nil
	}
	logf(cfg.silent, "  target IP %s", ip)

	wl, cleanup := wordlistPath(cfg.wordlist, dir)
	defer cleanup()
	outJSON := filepath.Join(dir, "vhosts.json")
	args := []string{"-w", wl + ":FUZZ", "-u", "https://" + ip + "/",
		"-H", "Host: FUZZ." + domain, "-H", "User-Agent: Mozilla/5.0",
		"-ac", "-mc", "200,204,301,302,307,401,403", "-s", "-of", "json", "-o", outJSON}
	if cfg.threads > 0 {
		args = append(args, "-t", itoa(cfg.threads))
	}
	runTool("ffuf", args...) // ffuf exit code varies; we read the JSON file

	b, err := os.ReadFile(outJSON)
	if err != nil {
		return nil
	}
	var res struct {
		Results []struct {
			Input map[string]string `json:"input"`
		} `json:"results"`
	}
	if json.Unmarshal(b, &res) != nil {
		return nil
	}
	var out []string
	for _, r := range res.Results {
		if f := r.Input["FUZZ"]; f != "" {
			out = append(out, f+"."+domain)
		}
	}
	return out
}

// tlsStage reads SSL certs from resolved hosts and extracts SAN/CN names.
func tlsStage(cfg config, domain string, hosts []string, dir string) []string {
	if len(hosts) == 0 {
		return nil
	}
	tmp := filepath.Join(dir, ".tls.tmp")
	writeLines(tmp, hosts)
	defer os.Remove(tmp)
	args := []string{"-l", tmp, "-san", "-cn", "-silent", "-nc"}
	if cfg.threads > 0 {
		args = append(args, "-c", itoa(cfg.threads))
	}
	lines, serr, err := runTool("tlsx", args...)
	if err != nil && len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "  %s✗%s tlsx failed: %s\n", red(), reset, firstLine(serr, err))
		return nil
	}
	// tlsx output: "host:443 [name]" — extract the bracketed name.
	var out []string
	for _, ln := range lines {
		ln = ansiRe.ReplaceAllString(ln, "")
		if i := strings.IndexByte(ln, '['); i >= 0 {
			if j := strings.IndexByte(ln[i:], ']'); j > 0 {
				out = append(out, strings.TrimSpace(ln[i+1:i+j]))
			}
		}
	}
	return out
}

// httpxRec is the subset of httpx JSON we care about.
type httpxRec struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	WebServer     string   `json:"webserver"`
	Host          string   `json:"host"`
	CDNName       string   `json:"cdn_name"`
}

// probeStage runs httpx on resolved hosts, writes alive.json (raw) + alive.txt (human).
func probeStage(cfg config, hosts []string, dir string) int {
	if len(hosts) == 0 {
		return 0
	}
	tmp := filepath.Join(dir, ".probe.tmp")
	writeLines(tmp, hosts)
	defer os.Remove(tmp)

	args := []string{"-l", tmp, "-silent", "-nc", "-json",
		"-sc", "-cl", "-title", "-td", "-cdn", "-cname", "-web-server", "-timeout", "10"}
	if cfg.threads > 0 {
		args = append(args, "-threads", itoa(cfg.threads))
	}
	lines, serr, err := runTool("httpx", args...)
	if err != nil && len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "  %s✗%s httpx failed: %s\n", red(), reset, firstLine(serr, err))
		return 0
	}

	// alive.json = raw json lines (machine-readable, for piping)
	writeLines(filepath.Join(dir, "alive.json"), lines)

	// alive.txt = human-readable, derived from the same json
	var txt []string
	for _, ln := range lines {
		var r httpxRec
		if json.Unmarshal([]byte(ln), &r) != nil || r.URL == "" {
			continue
		}
		parts := []string{r.URL, fmt.Sprintf("[%d]", r.StatusCode), fmt.Sprintf("[%dB]", r.ContentLength)}
		if r.Host != "" {
			parts = append(parts, "["+r.Host+"]")
		}
		fp := r.WebServer
		if len(r.Tech) > 0 {
			if fp != "" {
				fp += ","
			}
			fp += strings.Join(r.Tech, ",")
		}
		if fp != "" {
			parts = append(parts, "["+fp+"]")
		}
		if r.Title != "" {
			parts = append(parts, "["+r.Title+"]")
		}
		txt = append(txt, strings.Join(parts, " "))
	}
	sort.Strings(txt)
	writeLines(filepath.Join(dir, "alive.txt"), txt)
	return len(txt)
}

func parseDnsxResp(ln string) (host, ip string) {
	ln = ansiRe.ReplaceAllString(strings.TrimSpace(ln), "")
	if ln == "" {
		return "", ""
	}
	// host = first token; ip = first IP-looking match in the rest
	if i := strings.IndexAny(ln, " \t"); i > 0 {
		host = ln[:i]
		ip = ipRe.FindString(ln[i:])
	} else {
		host = ln
	}
	return host, ip
}

// runStream runs bin and reads stdout line-by-line AS IT ARRIVES, bumping the
// live counter (hbCount) per result so the heartbeat shows numbers climbing in
// real time. Empty lines are dropped (matching splitLines). On ctx timeout/cancel
// the process is killed and whatever was read so far is returned (partial kept).
// stdinNull closes stdin so a tool that would prompt gets EOF and bails.
func runStream(ctx context.Context, stdinNull bool, bin string, args ...string) (out []string, stderr string, err error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdinNull {
		cmd.Stdin = nil
	}
	var se bytes.Buffer
	cmd.Stderr = &se
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return nil, "", e
	}
	if e := cmd.Start(); e != nil {
		return nil, "", e
	}
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024) // some tool lines (httpx -json) are long
	for sc.Scan() {
		ln := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
		hbBump()
	}
	err = cmd.Wait()
	return out, strings.TrimSpace(se.String()), err
}

// runTool runs a binary, capturing stdout lines, stderr text, and exit error.
func runTool(bin string, args ...string) (out []string, stderr string, err error) {
	return runStream(context.Background(), false, bin, args...)
}

// runToolCtx is runTool with a hard timeout; on timeout the process is killed
// but any stdout read so far is returned (partial results are kept).
func runToolCtx(timeout time.Duration, bin string, args ...string) (out []string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runStream(ctx, false, bin, args...)
}

// ---- scope / exclude ----

type excluder struct{ res []*regexp.Regexp }

func loadExcluder(spec string) *excluder {
	e := &excluder{}
	if spec == "" {
		return e
	}
	var lines []string
	if fileExists(spec) {
		if b, err := os.ReadFile(spec); err == nil {
			lines = splitLines(string(b))
		}
	} else {
		lines = []string{spec}
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		// exact hostnames are valid regexes too; anchor them so "a.com" doesn't match "ba.com"
		pat := l
		if hostRe.MatchString(strings.ToLower(l)) {
			pat = "^" + regexp.QuoteMeta(strings.ToLower(l)) + "$"
		}
		if re, err := regexp.Compile(pat); err == nil {
			e.res = append(e.res, re)
		}
	}
	return e
}

func (e *excluder) match(name string) bool {
	for _, re := range e.res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// ---- normalize / helpers ----

func normalize(name, domain string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == domain {
		return name
	}
	if !strings.HasSuffix(name, "."+domain) {
		return ""
	}
	if !hostRe.MatchString(name) {
		return ""
	}
	return name
}

// missingNeeded returns required binaries for the active stages that aren't installed.
func missingNeeded(cfg config) []string {
	need := map[string]bool{}
	if cfg.passive {
		need["subfinder"] = true // core passive engine; others are optional
	}
	need["dnsx"] = true // resolve always runs
	if cfg.probe {
		need["httpx"] = true
	}
	if cfg.brute || cfg.perm {
		need["dnsx"] = true
	}
	if cfg.perm {
		need["alterx"] = true
	}
	if cfg.asn {
		need["asnmap"] = true
		need["mapcidr"] = true
	}
	if cfg.tls {
		need["tlsx"] = true
	}
	if cfg.vhost {
		need["ffuf"] = true
	}
	var miss []string
	for c := range need {
		if _, err := exec.LookPath(c); err != nil {
			miss = append(miss, c)
		}
	}
	sort.Strings(miss)
	return miss
}

// setupRunPath adds the go bin dir(s) to PATH so tools resolve by name.
func setupRunPath() {
	home, _ := os.UserHomeDir()
	cands := []string{filepath.Join(home, "go", "bin"), "/usr/local/go/bin"}
	if b, err := os.ReadFile(filepath.Join(home, ".subhound", ".setup-done")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			cands = append([]string{s}, cands...)
		}
	}
	for _, d := range cands {
		prependPath(d)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

func writeLines(path string, lines []string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] write %s: %v\n", path, err)
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstLine(stderr string, err error) string {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return err.Error()
	}
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func green() string {
	if reset == "" {
		return ""
	}
	return "\033[32m"
}
func red() string {
	if reset == "" {
		return ""
	}
	return "\033[31m"
}
