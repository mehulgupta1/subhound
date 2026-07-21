package main

// Step 3 — passive discovery + resolve + output, with per-source error surfacing
// (the no-false-zeros rule). Passive sources run in parallel; results merge/dedup
// in Go; dnsx resolves + strips wildcards.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		if d, _ := currentDir.Load().(string); d != "" {
			fmt.Fprintf(os.Stderr, "\n[!] interrupted — partial results saved in %s/\n", d)
		} else {
			fmt.Fprintln(os.Stderr, "\n[!] interrupted")
		}
		os.Exit(130)
	}()
}

// per-source hard wall-clock cap: a stuck source can't stall the phase.
// On timeout we keep whatever it already printed (partial results are fine).
// Fast default, but generous for -all (thorough mode legitimately takes longer).
func passiveTimeout(cfg config) time.Duration {
	if cfg.all {
		return 240 * time.Second
	}
	return 45 * time.Second
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
		logf(cfg.silent, "[b] BRUTEFORCE")
		added := addNames(set, bruteStage(cfg, domain, dir), domain, excl)
		logf(cfg.silent, "  → %d new resolving names", added)
		logf(cfg.silent, "")
		save()
	}

	// ---- PERMUTATION ---- (iterative alterx + resolve feedback loop)
	if cfg.perm {
		logf(cfg.silent, "[p] PERMUTATE (iterative)")
		added := addNames(set, permStage(cfg, domain, set, excl, dir), domain, excl)
		logf(cfg.silent, "  → %d new resolving names (total)", added)
		logf(cfg.silent, "")
		save()
	}

	// ---- ASN SWEEP ---- (owned IP space → reverse DNS)
	if cfg.asn {
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
	logf(cfg.silent, "[2] RESOLVE + wildcard filter")
	for h, ips := range resolveNames(cfg, domain, sortedKeys(set), dir) {
		resolved[h] = ips
	}
	logf(cfg.silent, "  → %d live subdomains", len(resolved))
	logf(cfg.silent, "")
	save()

	// ---- TLS HARVEST ---- (after resolve; reads certs from live hosts)
	if cfg.tls {
		logf(cfg.silent, "[t] TLS HARVEST")
		n := harvestInto(cfg, domain, set, excl, resolved, dir, tlsStage(cfg, domain, sortedKeys(resolved), dir))
		logf(cfg.silent, "  → %d new names from certs", n)
		logf(cfg.silent, "")
		save()
	}

	// ---- VHOST BRUTE ---- (hidden hosts on a shared IP)
	if cfg.vhost {
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
		logf(cfg.silent, "[3] PROBE (httpx)")
		aliveCount = probeStage(cfg, sortedKeys(resolved), dir)
		logf(cfg.silent, "  → %d alive hosts", aliveCount)
		logf(cfg.silent, "")
	}

	// ---- PUSH to dashboard ---- (resolve URL+key from flags/config/env)
	if !cfg.noPush {
		url, key := loadConfig().resolvePush(domain, cfg.project, cfg.pushURL, cfg.authKey)
		if url != "" && key != "" {
			logf(cfg.silent, "[→] PUSH to dashboard")
			ok := pushResults(cfg, domain, dir, url, key)
			// remember the settings after a successful first explicit push
			if ok && !cfg.noSave && cfg.pushURL != "" && cfg.authKey != "" {
				autoSave(domain, cfg.pushURL, cfg.authKey)
			}
			logf(cfg.silent, "")
		}
	}

	// summary
	logf(cfg.silent, "%s[✓]%s done — all:%d  resolved:%d  alive:%d", bold, reset, len(all), len(resolved), aliveCount)
	logf(cfg.silent, "    results in %s/", dir)

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
	// github-subdomains only if a token is set
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
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

func subfinderArgs(cfg config, domain string) []string {
	// -timeout caps how long subfinder waits on any single slow source (seconds).
	a := []string{"-d", domain, "-silent", "-timeout", "20"}
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

// maxPermIters caps the feedback loop so it always terminates.
const maxPermIters = 5

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
		cands := alterxGen(cfg, seeds, dir)
		if len(cands) == 0 {
			break
		}
		if len(cands) > permExplosionCap {
			fmt.Fprintf(os.Stderr, "  %s⚠%s  iter %d: %d candidates exceeds cap %d — stopping loop\n",
				red(), reset, iter, len(cands), permExplosionCap)
			break
		}
		var fresh []string
		for _, n := range dnsxResolveList(cfg, domain, cands, dir) {
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
	out, serr, err := runTool("alterx", "-l", seedFile, "-silent")
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
	// asnmap prompts for a PDCP key on stdin if none set — feed /dev/null so it
	// aborts instead of hanging, then detect the missing-key case.
	outLines, serr, _ := runToolStdinNull("asnmap", "-d", domain, "-silent")
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

// runToolStdinNull runs a tool with stdin closed (so interactive prompts abort).
func runToolStdinNull(bin string, args ...string) (out []string, stderr string, err error) {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = nil // empty stdin → prompts get EOF and bail instead of hanging
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return splitLines(so.String()), strings.TrimSpace(se.String()), err
}

// pushResults POSTs the httpx results (alive.json) to the dashboard, authenticated.
//
// API CONTRACT (implement this on the dashboard side):
//   POST <push-url>
//   Header: Authorization: Bearer <api-key>
//   Header: Content-Type: application/json
//   Body:   {"domain":"target.com","scanned_at":"<RFC3339>","count":N,
//            "hosts":[ <raw httpx JSON record>, ... ]}
//   Expect: 2xx on success.
// pushChunk caps hosts per request. One giant POST for a big scan blows the 30s
// timeout (and the Worker's body/CPU limits); several smaller POSTs never do.
const pushChunk = 5000

// pushResults POSTs alive.json to url with Bearer key, in chunks. Returns true if
// every chunk landed. Never loses data: results stay on disk; next scan re-pushes.
func pushResults(cfg config, domain, dir, url, key string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "alive.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s⚠%s  nothing to push (no probe results — remove -np)\n", red(), reset)
		return false
	}
	var hosts []json.RawMessage
	for _, ln := range splitLines(string(data)) {
		hosts = append(hosts, json.RawMessage(ln))
	}
	total := len(hosts)
	if total == 0 {
		logf(cfg.silent, "  no live hosts to push")
		return false
	}

	batches := (total + pushChunk - 1) / pushChunk
	for i := 0; i < total; i += pushChunk {
		batch := hosts[i:min(i+pushChunk, total)]
		if err := pushBatch(domain, url, key, batch); err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗%s push failed after %d/%d hosts: %v (results kept locally in %s)\n",
				red(), reset, i, total, err, dir)
			return false
		}
	}
	logf(cfg.silent, "  %s✓%s pushed %d hosts → dashboard (%d batch(es))", green(), reset, total, batches)
	return true
}

// pushBatch POSTs one chunk of hosts. 30s is ample now that each request carries
// at most pushChunk records.
func pushBatch(domain, url, key string, batch []json.RawMessage) error {
	payload, _ := json.Marshal(struct {
		Domain    string            `json:"domain"`
		ScannedAt string            `json:"scanned_at"`
		Count     int               `json:"count"`
		Hosts     []json.RawMessage `json:"hosts"`
	}{domain, time.Now().UTC().Format(time.RFC3339), len(batch), batch})

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("bad push URL: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "subhound/"+version)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("dashboard rejected: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

// runTool runs a binary, capturing stdout lines, stderr text, and exit error.
func runTool(bin string, args ...string) (out []string, stderr string, err error) {
	cmd := exec.Command(bin, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return splitLines(so.String()), strings.TrimSpace(se.String()), err
}

// runToolCtx is runTool with a hard timeout; on timeout the process is killed
// but any stdout captured so far is returned (partial results are kept).
func runToolCtx(timeout time.Duration, bin string, args ...string) (out []string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return splitLines(so.String()), strings.TrimSpace(se.String()), err
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
