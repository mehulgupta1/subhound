package main

// `subhound -cron` — schedule scans with the system's own cron (Linux/macOS) AND
// mirror them to BugHawk so you can see/stop/change them from the dashboard.
//   subhound -cron 12 -d hackerone.com   → run every 12 hours
//   subhound -cron off -d hackerone.com  → stop it
//   subhound -cron list                  → list scheduled scans
//   subhound -cron sync                  → report schedules + apply dashboard orders
//
// Cron fires HOURLY; the `-every N` gate (see main.go) makes it actually scan once
// per N hours. That lets intervals exceed 24h (plain cron can't) and survives
// reboots/missed fires by comparing against a last-run timestamp.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cronTag = "# subhound:"      // marks a scan line we own, per domain
const syncTag = "# subhound-sync"  // marks the self-sync line

func runCron(arg, domain, flPush, flAuth string) int {
	switch arg {
	case "list":
		return cronList()
	case "sync":
		return cronSync()
	}
	if domain == "" {
		fmt.Fprintln(os.Stderr, "-cron needs a target: subhound -cron 12 -d target.com")
		return 2
	}
	if arg == "off" {
		code := cronSet(domain, "")
		if url, key := loadConfig().resolvePush(domain, "", flPush, flAuth); url != "" && key != "" {
			reportSchedule(url, key, domain, 0) // tell BugHawk it's gone
		}
		return code
	}
	hours, err := strconv.Atoi(arg)
	if err != nil || hours < 1 || hours > 168 {
		fmt.Fprintln(os.Stderr, "-cron takes hours 1–168 (e.g. -cron 12), or 'off' / 'list' / 'sync'")
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot find subhound path: %v\n", err)
		return 1
	}
	url, key := loadConfig().resolvePush(domain, "", flPush, flAuth)
	if code := cronSet(domain, buildCronLine(exe, hours, domain, url, key)); code != 0 {
		return code
	}
	ensureSyncCron(exe) // so BugHawk sees this and can control it
	fmt.Fprintf(os.Stderr, "%s✓%s scheduled: %s every %dh\n", green(), reset, domain, hours)
	fmt.Fprintf(os.Stderr, "    logs: %s\n", logPath())
	if url != "" && key != "" {
		reportSchedule(url, key, domain, hours) // appear in BugHawk immediately
	} else {
		fmt.Fprintln(os.Stderr, "    note: no push key — scans locally only, won't show in BugHawk.")
	}
	return 0
}

func logPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".subhound")
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "cron.log")
}

// buildCronLine: fire hourly at a per-domain minute; -every N gates the real interval.
func buildCronLine(exe string, hours int, domain, url, key string) string {
	cmd := fmt.Sprintf("%q -d %s -every %d", exe, domain, hours)
	if url != "" && key != "" {
		cmd += fmt.Sprintf(" -push %s -auth %s", url, key)
	}
	return fmt.Sprintf("%d * * * * %s >> %q 2>&1 %s%s", domainMinute(domain), cmd, logPath(), cronTag, domain)
}

// ensureSyncCron adds a */5 line that reports schedules + applies dashboard commands.
func ensureSyncCron(exe string) {
	for _, l := range readCrontab() {
		if strings.Contains(l, syncTag) {
			return
		}
	}
	line := fmt.Sprintf("* * * * * %q -cron sync >> %q 2>&1 %s", exe, logPath(), syncTag) // every minute → snappy dashboard control
	writeCrontab(nonEmpty(append(readCrontab(), line)))
}

// domainMinute spreads scans across the hour (0-59) so targets don't all fire at :00.
func domainMinute(domain string) int {
	h := 0
	for _, c := range domain {
		h = (h*31 + int(c)) & 0x7fffffff
	}
	return h % 60
}

// cronSet replaces (or removes, if line=="") this domain's crontab entry.
func cronSet(domain, line string) int {
	var out []string
	for _, l := range readCrontab() {
		if strings.Contains(l, cronTag+domain) {
			continue
		}
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	if line != "" {
		out = append(out, line)
	}
	if err := writeCrontab(out); err != nil {
		fmt.Fprintf(os.Stderr, "%s✗%s could not update crontab: %v\n", red(), reset, err)
		fmt.Fprintln(os.Stderr, "    (is `cron` installed? on Linux: `sudo apt install cron && sudo service cron start`)")
		return 1
	}
	if line == "" {
		fmt.Fprintf(os.Stderr, "%s✓%s unscheduled: %s\n", green(), reset, domain)
	}
	return 0
}

func cronList() int {
	n := 0
	for _, l := range readCrontab() {
		i := strings.Index(l, cronTag)
		if i < 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-30s every %dh\n", strings.TrimSpace(l[i+len(cronTag):]), cronLineHours(l))
		n++
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "  no scheduled scans")
	}
	return 0
}

// --- sync: report schedules to the cloud + apply pending dashboard commands ---

func cronSync() int {
	exe, _ := os.Executable()
	for _, l := range readCrontab() {
		i := strings.Index(l, cronTag)
		if i < 0 {
			continue
		}
		domain := strings.TrimSpace(l[i+len(cronTag):])
		url, key := tokenAfter(l, "-push"), tokenAfter(l, "-auth")
		if url == "" || key == "" || domain == "" {
			continue // local-only cron: nothing to report
		}
		pending := reportSchedule(url, key, domain, cronLineHours(l))
		switch {
		case pending == "stop":
			cronSet(domain, "")
			reportSchedule(url, key, domain, 0)
			ackCommand(url, key)
			fmt.Fprintf(os.Stderr, "sync: stopped %s (dashboard)\n", domain)
		case strings.HasPrefix(pending, "set:"):
			if n, err := strconv.Atoi(strings.TrimPrefix(pending, "set:")); err == nil && n >= 1 && n <= 168 {
				cronSet(domain, buildCronLine(exe, n, domain, url, key))
				reportSchedule(url, key, domain, n)
				fmt.Fprintf(os.Stderr, "sync: %s -> every %dh (dashboard)\n", domain, n)
			}
			ackCommand(url, key)
		}
	}
	return 0
}

// cronLineHours reads the interval from "-every N"; falls back to the */N hour-field.
func cronLineHours(line string) int {
	if v := tokenAfter(line, "-every"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	if f := strings.Fields(line); len(f) >= 2 {
		if n, err := strconv.Atoi(strings.TrimPrefix(f[1], "*/")); err == nil {
			return n
		}
	}
	return 0
}

// tokenAfter returns the whitespace-token following flag, or "".
func tokenAfter(line, flag string) string {
	f := strings.Fields(line)
	for i := 0; i < len(f)-1; i++ {
		if f[i] == flag {
			return f[i+1]
		}
	}
	return ""
}

// cronGateAllows reports whether N hours passed since this domain last ran, and if
// so records "now". Lets cron fire hourly but scan once per N hours (see main.go).
func cronGateAllows(domain string, hours int) bool {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".subhound")
	os.MkdirAll(dir, 0o755)
	stamp := filepath.Join(dir, "lastrun-"+fileSafe(domain))
	if b, err := os.ReadFile(stamp); err == nil {
		if last, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			if time.Now().Unix()-last < int64(hours)*3600-300 { // 5-min margin for cron drift
				return false
			}
		}
	}
	os.WriteFile(stamp, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
	return true
}

func fileSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("/\\: ", r) {
			return '_'
		}
		return r
	}, s)
}

func nonEmpty(in []string) []string {
	var out []string
	for _, l := range in {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// --- tiny cloud client for schedule/command ---

func cloudBase(pushURL string) string {
	return strings.TrimSuffix(strings.TrimSuffix(pushURL, "/"), "/ingest")
}

// reportSchedule POSTs this domain's interval (domain lets the cloud auto-create the
// project so it shows immediately); returns any pending dashboard command.
func reportSchedule(pushURL, key, domain string, hours int) string {
	if m := postCloud(cloudBase(pushURL)+"/schedule", key, map[string]any{"hours": hours, "domain": domain}); m != nil {
		if s, ok := m["pending_cmd"].(string); ok {
			return s
		}
	}
	return ""
}

func ackCommand(pushURL, key string) {
	postCloud(cloudBase(pushURL)+"/ack", key, map[string]int{})
}

func postCloud(url, key string, body any) map[string]any {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "subhound/"+version)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil // cloud unreachable → local cron still runs; report retries next sync
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var m map[string]any
	json.Unmarshal(data, &m)
	return m
}

func readCrontab() []string {
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return nil // no crontab yet → treat as empty
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

func writeCrontab(lines []string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	return cmd.Run()
}
