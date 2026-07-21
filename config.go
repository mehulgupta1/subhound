package main

// Dashboard config: remembers your dashboard URL + per-project API keys so that
// after the first push you can just run `subhound -d target.com`. Stored as JSON
// (stdlib, no dependency) at ~/.config/subhound/config.json, mode 0600.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type projectCfg struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	Domains []string `json:"domains"`
}

type dashConfig struct {
	DashboardURL string       `json:"dashboard_url"`
	Projects     []projectCfg `json:"projects"`
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "subhound", "config.json")
}

func loadConfig() dashConfig {
	var c dashConfig
	if b, err := os.ReadFile(configPath()); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func saveConfig(c dashConfig) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

// resolvePush decides the URL + key for a run. Order (most specific wins):
// -auth flag → -project flag → domain match in config → env → none.
func (c dashConfig) resolvePush(domain, project, flagURL, flagKey string) (url, key string) {
	url = flagURL
	if url == "" {
		url = c.DashboardURL
	}
	if url == "" {
		url = os.Getenv("SUBHOUND_DASHBOARD_URL")
	}

	key = flagKey
	if key == "" && project != "" {
		for _, p := range c.Projects {
			if strings.EqualFold(p.Name, project) {
				key = p.Key
			}
		}
	}
	if key == "" && domain != "" {
		for _, p := range c.Projects {
			for _, d := range p.Domains {
				if strings.EqualFold(d, domain) {
					key = p.Key
				}
			}
		}
	}
	if key == "" {
		key = os.Getenv("SUBHOUND_API_KEY")
	}
	return url, key
}

// autoSave remembers the URL + key for a domain after a first explicit push,
// so next time `subhound -d domain` just works.
func autoSave(domain, url, key string) {
	c := loadConfig()
	c.DashboardURL = url
	name := projectName(domain)
	// update existing project (by domain or name), else add
	for i := range c.Projects {
		if strings.EqualFold(c.Projects[i].Name, name) || containsFold(c.Projects[i].Domains, domain) {
			c.Projects[i].Key = key
			if !containsFold(c.Projects[i].Domains, domain) {
				c.Projects[i].Domains = append(c.Projects[i].Domains, domain)
			}
			if saveConfig(c) == nil {
				fmt.Fprintf(os.Stderr, "  %s✓%s saved — next time just run:  subhound -d %s\n", green(), reset, domain)
			}
			return
		}
	}
	c.Projects = append(c.Projects, projectCfg{Name: name, Key: key, Domains: []string{domain}})
	if saveConfig(c) == nil {
		fmt.Fprintf(os.Stderr, "  %s✓%s saved — next time just run:  subhound -d %s\n", green(), reset, domain)
	}
}

func projectName(domain string) string {
	if i := strings.IndexByte(domain, '.'); i > 0 {
		return domain[:i]
	}
	return domain
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// runCheck implements `subhound -check`. With -d, checks that one project's key;
// without -d, checks the dashboard + every saved project.
func runCheck(domain, flagURL, flagKey string) int {
	c := loadConfig()
	url, _ := c.resolvePush(domain, "", flagURL, "")
	if url == "" {
		fmt.Fprintln(os.Stderr, "✗ no dashboard URL — pass -push <url> or set one up first")
		return 1
	}
	base := strings.TrimSuffix(url, "/ingest")

	// dashboard reachable?
	if !ping(base + "/health") {
		fmt.Fprintf(os.Stderr, "✗ dashboard offline: %s\n", base)
		return 1
	}
	fmt.Fprintf(os.Stderr, "✓ Dashboard reachable: %s\n", base)

	// which keys to check?
	type kd struct{ label, key string }
	var checks []kd
	if domain != "" || flagKey != "" {
		_, key := c.resolvePush(domain, "", flagURL, flagKey)
		if key == "" {
			fmt.Fprintf(os.Stderr, "✗ no key for %s (add it, or pass -auth)\n", domain)
			return 1
		}
		label := domain
		if label == "" {
			label = "(provided key)"
		}
		checks = append(checks, kd{label, key})
	} else {
		for _, p := range c.Projects {
			label := p.Name
			if len(p.Domains) > 0 {
				label = p.Domains[0]
			}
			checks = append(checks, kd{label, p.Key})
		}
	}
	if len(checks) == 0 {
		fmt.Fprintln(os.Stderr, "  (no projects saved yet — push once with -push/-auth to add one)")
		return 0
	}

	bad := 0
	for _, ch := range checks {
		name, ok := whoamiCheck(base+"/whoami", ch.key)
		if ok {
			fmt.Fprintf(os.Stderr, "  %-24s %s🟢 key valid%s (project: %s)\n", ch.label, green(), reset, name)
		} else {
			bad++
			fmt.Fprintf(os.Stderr, "  %-24s %s🔴 key rejected%s\n", ch.label, red(), reset)
		}
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func ping(url string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func whoamiCheck(url, key string) (project string, ok bool) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	var r struct {
		Project string `json:"project"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	return r.Project, true
}
