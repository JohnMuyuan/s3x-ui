// Package mtproto runs MTProto FakeTLS proxies for Telegram with mtg-multi
// (github.com/mhsanaei/mtg-multi). Neither Xray nor sing-box speaks MTProto,
// so each mtproto inbound is one mtg process serving every enabled client's
// secret. Client changes are pushed through mtg's API, which keeps the other
// clients' connections and closes those of removed or disabled clients.
package mtproto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"x-ui/database/model"
)

// Secret is one client: Name is its email, which mtg also reports stats by.
type Secret struct {
	Name   string
	Secret string
}

// Instance is what one mtproto inbound needs mtg to run.
type Instance struct {
	Id       int
	Tag      string
	Listen   string
	Port     int
	Secrets  []Secret
	PreferIP string
	// FrontingHost and FrontingPort receive connections that fail the FakeTLS
	// handshake; empty sends them to the FakeTLS domain itself.
	FrontingHost   string
	FrontingPort   int
	MaxConnections int
	// Proxy is a socks5:// URL mtg reaches Telegram through, or empty.
	Proxy string
}

// SecretFor builds a client's FakeTLS secret: "ee", its 16 random bytes and
// the FakeTLS domain, all in hex. Telegram clients read the domain from it.
func SecretFor(key, domain string) (string, error) {
	if b, err := hex.DecodeString(key); err != nil || len(b) != 16 {
		return "", fmt.Errorf("client key must be 32 hex characters")
	}
	if domain == "" {
		return "", fmt.Errorf("no FakeTLS domain")
	}
	return "ee" + strings.ToLower(key) + hex.EncodeToString([]byte(domain)), nil
}

// FromInbound derives the instance for an inbound; false when it is not an
// enabled mtproto inbound with at least one usable client. Clients are
// skipped when disabled by hand or by the panel (quota, expiry).
func FromInbound(ib *model.Inbound, proxy string) (Instance, []string, bool) {
	if ib == nil || !ib.Enable || ib.Protocol != model.MTProto {
		return Instance{}, nil, false
	}
	var s struct {
		FakeTLSDomain  string `json:"fakeTlsDomain"`
		PreferIP       string `json:"preferIp"`
		FrontingHost   string `json:"frontingHost"`
		FrontingPort   int    `json:"frontingPort"`
		MaxConnections int    `json:"maxConnections"`
		Clients        []struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Enable   bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(ib.Settings), &s); err != nil {
		return Instance{}, []string{err.Error()}, false
	}
	disabled := map[string]bool{}
	for _, st := range ib.ClientStats {
		if !st.Enable {
			disabled[st.Email] = true
		}
	}
	var problems []string
	inst := Instance{
		Id: ib.Id, Tag: ib.Tag, Listen: ib.Listen, Port: ib.Port,
		PreferIP: s.PreferIP, FrontingHost: s.FrontingHost, FrontingPort: s.FrontingPort,
		MaxConnections: s.MaxConnections, Proxy: proxy,
	}
	for _, c := range s.Clients {
		if !c.Enable || disabled[c.Email] || c.Email == "" {
			continue
		}
		secret, err := SecretFor(c.Password, strings.TrimSpace(s.FakeTLSDomain))
		if err != nil {
			problems = append(problems, fmt.Sprintf("client %s: %v", c.Email, err))
			continue
		}
		inst.Secrets = append(inst.Secrets, Secret{Name: c.Email, Secret: secret})
	}
	return inst, problems, len(inst.Secrets) > 0
}

func (inst Instance) bindTo() string {
	listen := inst.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	if strings.Contains(listen, ":") {
		listen = "[" + listen + "]"
	}
	return listen + ":" + strconv.Itoa(inst.Port)
}

// structure covers everything but the secrets, which mtg takes live.
func (inst Instance) structure() string {
	return strings.Join([]string{inst.bindTo(), inst.PreferIP, inst.FrontingHost,
		strconv.Itoa(inst.FrontingPort), strconv.Itoa(inst.MaxConnections), inst.Proxy}, "|")
}

func (inst Instance) secrets() string {
	pairs := make([]string, 0, len(inst.Secrets))
	for _, e := range inst.Secrets {
		pairs = append(pairs, e.Name+"="+e.Secret)
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "|")
}

// render writes mtg's TOML. Top-level keys come before any table, and
// [secrets] goes last so no later key falls into it.
func render(inst Instance, apiPort int, apiToken string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "bind-to = %q\n", inst.bindTo())
	// mtg prefers IPv6 by default. Through Xray's SOCKS bridge an unreachable
	// IPv6 DC is a reset rather than an error mtg falls back from, and most
	// servers have IPv4, so IPv4 goes first unless chosen otherwise.
	preferIP := inst.PreferIP
	if preferIP == "" {
		preferIP = "prefer-ipv4"
	}
	fmt.Fprintf(&b, "prefer-ip = %q\n", preferIP)
	fmt.Fprintf(&b, "api-bind-to = \"127.0.0.1:%d\"\n", apiPort)
	fmt.Fprintf(&b, "api-token = %q\n", apiToken)
	if inst.FrontingHost != "" || inst.FrontingPort > 0 {
		b.WriteString("\n[domain-fronting]\n")
		if inst.FrontingHost != "" {
			fmt.Fprintf(&b, "host = %q\n", inst.FrontingHost)
		}
		if inst.FrontingPort > 0 {
			fmt.Fprintf(&b, "port = %d\n", inst.FrontingPort)
		}
	}
	if inst.Proxy != "" {
		fmt.Fprintf(&b, "\n[network]\nproxies = [%q]\n", inst.Proxy)
	}
	if inst.MaxConnections > 0 {
		fmt.Fprintf(&b, "\n[throttle]\nmax-connections = %d\n", inst.MaxConnections)
	}
	b.WriteString("\n[secrets]\n")
	for _, e := range inst.Secrets {
		fmt.Fprintf(&b, "%q = %q\n", e.Name, e.Secret)
	}
	return b.String()
}

func writeConfig(inst Instance, apiPort int, apiToken string) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(configPath(inst.Id), []byte(render(inst, apiPort, apiToken)), 0o600)
}

var apiClient = http.Client{Timeout: 3 * time.Second}

func apiRequest(method string, port int, token, path string, body any) (*http.Response, error) {
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), &payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return apiClient.Do(req)
}

// putSecrets swaps the secret set of a running mtg in place.
func putSecrets(port int, token string, inst Instance) bool {
	type entry struct {
		Secret string `json:"secret"`
	}
	secrets := make(map[string]entry, len(inst.Secrets))
	for _, e := range inst.Secrets {
		secrets[e.Name] = entry{e.Secret}
	}
	resp, err := apiRequest(http.MethodPut, port, token, "/secrets", map[string]any{"secrets": secrets})
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type userStats struct {
	Connections int64 `json:"connections"`
	BytesIn     int64 `json:"bytes_in"`
	BytesOut    int64 `json:"bytes_out"`
}

// stats returns mtg's cumulative per-client counters.
func stats(port int, token string) (map[string]userStats, bool) {
	resp, err := apiRequest(http.MethodGet, port, token, "/stats", nil)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var parsed struct {
		Users map[string]userStats `json:"users"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&parsed) != nil {
		return nil, false
	}
	return parsed.Users, true
}
