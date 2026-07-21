# SubHound 🐾

**Advanced subdomain enumeration for Linux & macOS.**

SubHound is a single Go binary that orchestrates the best open-source recon
tools into one fast pipeline:

```
discover  →  resolve  →  probe  →  save
(passive/brute/perm/asn)   (dnsx)   (httpx)   (local files)
```

It finds subdomains from many sources, resolves them (dropping DNS wildcards),
checks which are alive over HTTP(S), and writes clean result files — with
**per-source error reporting** so a silent failure never looks like "0 found".

---

## Requirements

- **Linux or macOS** (Windows is not supported — the recon tools are \*nix-only)
- **Go** — installed automatically by `-setup` if you don't have it

---

## Install

```bash
# 1. get the code
git clone https://github.com/mehulgupta1/subhound.git
cd subhound

# 2. build the binary (needs Go)
go build -o subhound .

# 3. install the recon tools it calls (subfinder, dnsx, httpx, …)
./subhound -setup
```

`-setup` is **idempotent** (only installs what's missing) and **fail-soft**
(an optional tool failing never aborts the rest). After it finishes, add Go's
bin dir to your PATH if it isn't already:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Tools it installs

| Required (pipeline needs these) | Optional (extra power) |
|---|---|
| `subfinder` — passive sources | `assetfinder` — more passive |
| `dnsx` — DNS resolution (fallback + PTR/IPs) | `alterx` — permutation engine (`-perm`) |
| `httpx` — HTTP probing | `github-subdomains` — GitHub source |
| `anew` — dedup merging | `tlsx` — cert harvesting (`-tls`) |
| `asnmap` — ASN lookup (`-asn`) | `ffuf` — vhost brute (`-vhost`) |
| `mapcidr` — CIDR expansion | `findomain` — extra passive |
| | `shuffledns` + `massdns` — **fast** bulk resolving |

`-setup` also downloads the [Trickest resolver list](https://github.com/trickest/resolvers)
to `~/.subhound/resolvers.txt`.

### Fast resolving (massdns)

Permutation (`-perm`) can generate **hundreds of thousands** of guesses. If
`shuffledns` + `massdns` are installed, subhound resolves them with massdns
(the big resolver list for speed + a trusted list to verify) — **~300k names in
~40s instead of ~30+ min** with dnsx. If they're missing, it falls back to dnsx
automatically. Cap the guesses per round with `-perm-limit` (default 300000).

---

## API keys (optional, but recommended)

Some passive sources return **far more** results with a free API key. Store
them once:

```bash
./subhound -config
```

It asks for (blank to skip): **Chaos/PDCP**, **GitHub token**,
**SecurityTrails**, **VirusTotal** — and writes them where the tools read them
(subfinder's `provider-config.yaml`). The **Chaos/PDCP** key also enables the
ASN sweep (`asnmap`), so add it if you want `-asn`.

---

## Quick start

```bash
# simplest — passive discovery + resolve + probe
./subhound -d target.com

# everything on (thorough): all passive sources + brute + perm + asn
./subhound -d target.com -all -brute -perm -asn

# many targets from a file
./subhound -l domains.txt

# pipe-friendly: just print live subdomains, no banner/logs
cat domains.txt | ./subhound -silent
```

By default SubHound runs **passive discovery + resolve + HTTP probe**. The
heavier stages (`-brute`, `-perm`, `-asn`, `-tls`, `-vhost`) are opt-in.

---

## Features — what each flag does

### Input
| Flag | What it does |
|---|---|
| `-d`, `-domain` | single target domain |
| `-l`, `-list` | file of domains, one per line (stdin also works) |
| `-exclude` | out-of-scope list/regex to **drop** from results |

### Discovery (find subdomains)
| Flag | What it does |
|---|---|
| *(default)* | **passive** sources (subfinder, findomain, assetfinder, …) |
| `-all` | enable **all** passive sources (slower, more thorough) |
| `-brute` | DNS **bruteforce** with a wordlist (bundled, or `-w`) |
| `-perm` | **permutation**/mutation — mangles known names to find siblings |
| `-asn` | **ASN + reverse-DNS** sweep over the target's owned IP space |
| `-recursive` | extra brute/perm pass over **newly found** subdomains |

### Probe & extras
| Flag | What it does |
|---|---|
| *(default)* | **HTTP probe** with httpx — which hosts are actually alive |
| `-tls` | harvest names from **TLS certificates** (SAN/CN) of live hosts |
| `-vhost` | **virtual-host** bruteforce against a shared IP |

### Toggles (turn defaults off)
| Flag | What it does |
|---|---|
| `-no-passive` | skip passive sources (e.g. brute-only mode) |
| `-np`, `-no-probe` | skip the HTTP probe (discovery + resolve only) |

### Options
| Flag | What it does |
|---|---|
| `-w`, `-wordlist` | wordlist for `-brute` (default: bundled) |
| `-pw`, `-perm-words` | token list for `-perm` (default: bundled) |
| `-r`, `-resolvers` | custom DNS resolvers file |
| `-t`, `-threads` | concurrency (default 100) |
| `-o`, `-output` | output directory |
| `-json` | also emit JSON |
| `-silent` | print subdomains only — no banner/logs (pipe-friendly) |
| `-setup` | install/verify tools, then exit |
| `-config` | save API keys into subfinder config |
| `-version` | print version |
| `-h`, `-help` | show help |

---

## Output

Each run writes a folder `subhound-<domain>-<timestamp>/` containing:

| File | Contents |
|---|---|
| `all-subdomains.txt` | every unique subdomain discovered |
| `resolved.txt` | resolved hosts with their IPs (`host  ip1,ip2`) |
| `alive.txt` | live HTTP(S) hosts, human-readable |
| `alive.json` | live hosts as raw httpx JSON (for piping/parsing) |
| `vhosts.json` | virtual-host findings (only with `-vhost`) |

Results are saved **incrementally after each stage**, so if you hit `Ctrl-C`
(or a crash), whatever finished so far is already on disk.

---

## Examples

```bash
# fast recon, no probe (just the name list)
./subhound -d target.com -np

# brute-force only (skip passive), no probe
./subhound -d target.com -brute -no-passive -np

# thorough + cert harvesting + custom wordlist
./subhound -d target.com -all -brute -perm -tls -w big-wordlist.txt

# scope-aware: drop out-of-scope hosts
./subhound -d target.com -all -exclude out-of-scope.txt
```

---

## License

Personal recon tooling — use responsibly and only against targets you are
authorized to test.
