// SubHound — advanced subdomain enumeration orchestrator (Linux/macOS).
// Step 1: CLI skeleton — flags, banner, help, mode resolution, input loading,
// output dir. The pipeline stages are wired in the following build steps.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func timestamp() string { return time.Now().Format("20060102-150405") }
func itoa(n int) string { return strconv.Itoa(n) }

// orEnv returns v if non-empty, else the named environment variable.

const version = "1.0.0"
const author = "<your-handle>" // ponytail: single edit point — change to your name/handle

// Banner is a raw string; the "d" glyph contains a backtick, so we splice it in.
const banner = `
   ____        _     _   _                       _
  / ___| _   _| |__ | | | | ___  _   _ _ __   __| |
  \___ \| | | | '_ \| |_| |/ _ \| | | | '_ \ / _` + "`" + ` |
   ___) | |_| | |_) |  _  | (_) | |_| | | | | (_| |
  |____/ \__,_|_.__/|_| |_|\___/ \__,_|_| |_|\__,_|
`

// ANSI colors (target is *nix terminals). Emptied by disableColors() when the
// output isn't an interactive terminal, so piped/redirected output stays clean.
var (
	cyan  = "\033[36m"
	bold  = "\033[1m"
	reset = "\033[0m"
)

func disableColors() {
	cyan, bold, reset = "", "", ""
}

// config holds resolved flags/modes for a run.
type config struct {
	domains   []string
	wordlist  string
	permWords string
	resolvers string
	exclude   string
	outDir    string
	threads   int
	all       bool
	brute     bool
	perm      bool
	asn       bool
	tls       bool
	vhost     bool
	recursive bool
	passive   bool // default true, off with -no-passive
	probe     bool // default true, off with -np
	json      bool
	silent    bool
}

func main() {
	var (
		flDomain, flList                          string
		flWord, flPerm, flResolvers, flExclude    string
		flOut                                     string
		flThreads                                 int
		flAll, flBrute, flPerm2, flAsn, flTls      bool
		flVhost, flRecursive                      bool
		flNoPassive, flNoProbe                    bool
		flJSON, flSilent, flSetup, flConfig, flVer bool
	)

	flag.StringVar(&flDomain, "d", "", "")
	flag.StringVar(&flDomain, "domain", "", "")
	flag.StringVar(&flList, "l", "", "")
	flag.StringVar(&flList, "list", "", "")
	flag.StringVar(&flExclude, "exclude", "", "")

	flag.BoolVar(&flAll, "all", false, "")
	flag.BoolVar(&flBrute, "brute", false, "")
	flag.BoolVar(&flPerm2, "perm", false, "")
	flag.BoolVar(&flAsn, "asn", false, "")
	flag.BoolVar(&flTls, "tls", false, "")
	flag.BoolVar(&flVhost, "vhost", false, "")
	flag.BoolVar(&flRecursive, "recursive", false, "")

	flag.BoolVar(&flNoPassive, "no-passive", false, "")
	flag.BoolVar(&flNoProbe, "np", false, "")
	flag.BoolVar(&flNoProbe, "no-probe", false, "")

	flag.StringVar(&flWord, "w", "", "")
	flag.StringVar(&flWord, "wordlist", "", "")
	flag.StringVar(&flPerm, "pw", "", "")
	flag.StringVar(&flPerm, "perm-words", "", "")
	flag.StringVar(&flResolvers, "r", "", "")
	flag.StringVar(&flResolvers, "resolvers", "", "")
	flag.IntVar(&flThreads, "t", 100, "")
	flag.IntVar(&flThreads, "threads", 100, "")
	flag.StringVar(&flOut, "o", "", "")
	flag.StringVar(&flOut, "output", "", "")

	flag.BoolVar(&flJSON, "json", false, "")
	flag.BoolVar(&flSilent, "silent", false, "")
	flag.BoolVar(&flSetup, "setup", false, "")
	flag.BoolVar(&flConfig, "config", false, "")
	flag.BoolVar(&flVer, "version", false, "")

	flag.Usage = printHelp
	flag.Parse()

	if flVer {
		fmt.Printf("subhound %s\n", version)
		return
	}

	if flSilent || !isTerminal(os.Stderr) {
		disableColors()
	}
	printBanner(flSilent)

	if flSetup {
		os.Exit(runSetup())
	}
	if flConfig {
		os.Exit(runConfig())
	}

	domains := loadDomains(flDomain, flList)
	if len(domains) == 0 {
		printHelp()
		os.Exit(2)
	}

	cfg := config{
		domains:   domains,
		wordlist:  flWord,
		permWords: flPerm,
		resolvers: flResolvers,
		exclude:   flExclude,
		outDir:    flOut,
		threads:   flThreads,
		all:       flAll,
		brute:     flBrute,
		perm:      flPerm2,
		asn:       flAsn,
		tls:       flTls,
		vhost:     flVhost,
		recursive: flRecursive,
		passive:   !flNoPassive,
		probe:     !flNoProbe,
		json:      flJSON,
		silent:    flSilent,
	}

	installInterruptHandler() // Ctrl-C → keep partial results, exit clean

	exit := 0
	for _, d := range cfg.domains {
		if c := runPipeline(cfg, d); c > exit {
			exit = c
		}
	}
	os.Exit(exit)
}

// modeList returns the ordered list of active stages for display.
func modeList(cfg config) []string {
	var m []string
	if cfg.passive {
		if cfg.all {
			m = append(m, "passive(all)")
		} else {
			m = append(m, "passive")
		}
	}
	if cfg.brute {
		m = append(m, "brute")
	}
	if cfg.perm {
		m = append(m, "perm")
	}
	if cfg.asn {
		m = append(m, "asn")
	}
	if cfg.tls {
		m = append(m, "tls")
	}
	if cfg.vhost {
		m = append(m, "vhost")
	}
	if cfg.recursive {
		m = append(m, "recursive")
	}
	m = append(m, "resolve")
	if cfg.probe {
		m = append(m, "probe")
	}
	return m
}

// loadDomains gathers targets from -d, -l file, and stdin (deduped, lowercased).
func loadDomains(domain, list string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(s, ".")
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	if domain != "" {
		add(domain)
	}
	if list != "" {
		f, err := os.Open(list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot open list %s: %v\n", list, err)
			os.Exit(1)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	// Read stdin ONLY when no -d/-l given AND stdin is piped. Guarding on
	// (domain=="" && list=="") stops us blocking on stdin when the user already
	// supplied a target — otherwise a non-TTY stdin (e.g. under a runner) hangs.
	if domain == "" && list == "" && !isTerminal(os.Stdin) {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			add(sc.Text())
		}
	}

	sort.Strings(out)
	return out
}

// logf prints a status line to stderr unless silent (stdout stays clean for piping).
func logf(silent bool, format string, a ...any) {
	if silent {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

func printBanner(silent bool) {
	if silent || !isTerminal(os.Stderr) {
		return
	}
	fmt.Fprint(os.Stderr, cyan+banner+reset)
	fmt.Fprintf(os.Stderr, "         Advanced Subdomain Enumeration  ·  v%s\n", version)
	fmt.Fprintf(os.Stderr, "                    by %s\n\n", author)
}

// isTerminal reports whether f is an interactive terminal (not piped/redirected).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func printHelp() {
	// Banner first (plain, so `subhound -h > file` stays readable).
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "         Advanced Subdomain Enumeration  ·  v%s\n", version)
	fmt.Fprintf(os.Stderr, "                    by %s\n", author)
	fmt.Fprint(os.Stderr, `
USAGE:
  subhound -d target.com [flags]

INPUT:
  -d, -domain      target domain
  -l, -list        file of domains, one per line   (stdin also supported)
  -exclude         out-of-scope list/regex to DROP from results

DISCOVERY:
  -all             enable all passive sources
  -brute           DNS bruteforce (built-in wordlist or -w)
  -perm            permutation / mutation discovery
  -asn             ASN + reverse-DNS sweep
  -recursive       extra brute/perm pass over newly found subs

PROBE & EXTRAS:
  -tls             cert (SAN/CN) harvesting
  -vhost           virtual-host bruteforce

TOGGLES (turn default stages off — solo-mode):
  -no-passive      skip passive sources
  -np, -no-probe   skip the HTTP probe (probe runs by DEFAULT)

OPTIONS:
  -w,  -wordlist   wordlist for -brute   (default: bundled)
  -pw, -perm-words token list for -perm  (default: bundled)
  -r,  -resolvers  custom resolvers file
  -t,  -threads    concurrency               (default 100)
  -o,  -output     output directory
  -json            also emit JSON
  -silent          print subdomains only — no banner/logs (pipe-friendly)
  -setup           install/verify tools, then exit
  -config          save API keys into subfinder config
  -version         print version
  -h, -help        show this help

EXAMPLES:
  subhound -d target.com
  subhound -d target.com -np
  subhound -d target.com -brute -no-passive -np
  subhound -d target.com -all -brute -perm -asn
  cat domains.txt | subhound -silent
`)
}
