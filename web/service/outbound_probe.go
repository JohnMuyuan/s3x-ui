package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"x-ui/util/json_util"
	"x-ui/util/random"
	"x-ui/xray"
)

// Outbounds are tested inside the running Xray, so a test sees exactly what
// traffic routed there sees, and a WARP outbound is not raced by a second
// copy of its keys. One loopback SOCKS inbound takes the tests; each
// outbound has its own account, and a routing rule on that account sends the
// connection to the outbound.
const (
	OutboundProbeTag   = "outbound-probe"
	outboundProbePort  = 62793
	OutboundProbeUser  = "s3x-probe-"
	outboundProbeLevel = 9 // a level with no policy, so no per-user stats

	DefaultOutboundTestURL = "https://www.gstatic.com/generate_204"
	outboundSpeedURL       = "https://speed.cloudflare.com/__down?bytes=50000000"
	outboundProbeTimeout   = 10 * time.Second
	outboundSpeedDuration  = 10 * time.Second
)

var outboundProbePassword = random.Seq(24)

// outbounds a request can be sent through to see whether it works
func probeable(protocol string) bool {
	switch protocol {
	case "blackhole", "dns", "loopback", "":
		return false
	}
	return true
}

func injectOutboundProbe(cfg *xray.Config) {
	for _, ib := range cfg.InboundConfigs {
		if ib.Port == outboundProbePort {
			return
		}
	}
	var outbounds []struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
	}
	json.Unmarshal(cfg.OutboundConfigs, &outbounds)
	var accounts []map[string]string
	var rules []any
	for _, ob := range outbounds {
		if ob.Tag == "" || !probeable(ob.Protocol) {
			continue
		}
		user := OutboundProbeUser + ob.Tag
		accounts = append(accounts, map[string]string{"user": user, "pass": outboundProbePassword})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{OutboundProbeTag}, "user": []string{user}, "outboundTag": ob.Tag})
	}
	if len(accounts) == 0 {
		return
	}
	routing := map[string]any{}
	if len(cfg.RouterConfig) > 0 && json.Unmarshal(cfg.RouterConfig, &routing) != nil {
		return
	}
	existing, _ := routing["rules"].([]any)
	routing["rules"] = append(rules, existing...)
	raw, err := json.Marshal(routing)
	if err != nil {
		return
	}
	settings, _ := json.Marshal(map[string]any{"auth": "password", "accounts": accounts, "udp": false, "userLevel": outboundProbeLevel})
	cfg.RouterConfig = raw
	cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     outboundProbePort,
		Protocol: "socks",
		Settings: settings,
		Tag:      OutboundProbeTag,
	})
}

type OutboundProbeResult struct {
	Tag       string `json:"tag"`
	OK        bool   `json:"ok"`
	DelayMs   int    `json:"delayMs"`
	SpeedKBps int    `json:"speedKBps,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt int64  `json:"checkedAt"`
}

var outboundStatus = struct {
	sync.Mutex
	m map[string]*OutboundProbeResult
}{m: map[string]*OutboundProbeResult{}}

// OutboundStatus is the latest result of each outbound tested.
func OutboundStatus() map[string]*OutboundProbeResult {
	outboundStatus.Lock()
	defer outboundStatus.Unlock()
	out := make(map[string]*OutboundProbeResult, len(outboundStatus.m))
	for tag, r := range outboundStatus.m {
		copied := *r
		out[tag] = &copied
	}
	return out
}

// ProbeableOutbounds are the outbounds the running Xray can test.
func ProbeableOutbounds() []string {
	if p == nil || !p.IsRunning() {
		return nil
	}
	for _, ib := range p.GetConfig().InboundConfigs {
		if ib.Tag != OutboundProbeTag {
			continue
		}
		var settings struct {
			Accounts []struct {
				User string `json:"user"`
			} `json:"accounts"`
		}
		json.Unmarshal(ib.Settings, &settings)
		tags := make([]string, 0, len(settings.Accounts))
		for _, a := range settings.Accounts {
			tags = append(tags, strings.TrimPrefix(a.User, OutboundProbeUser))
		}
		return tags
	}
	return nil
}

// ProbeOutbound requests testURL through an outbound and, with speed set,
// downloads through it for a few seconds. Any HTTP response counts as
// working; the delay is that of a second request on the open connection, the
// round trip through the established tunnel.
func ProbeOutbound(tag, testURL string, speed bool) *OutboundProbeResult {
	res := &OutboundProbeResult{Tag: tag, CheckedAt: time.Now().UnixMilli()}
	defer func() {
		outboundStatus.Lock()
		if prev := outboundStatus.m[tag]; prev != nil && !speed && res.OK {
			res.SpeedKBps = prev.SpeedKBps // a delay check keeps the last speed
		}
		copied := *res
		outboundStatus.m[tag] = &copied
		outboundStatus.Unlock()
	}()
	client, err := probeClient(tag)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer client.CloseIdleConnections()
	if testURL == "" {
		testURL = DefaultOutboundTestURL
	}

	delay := -1
	for i := 0; i < 2; i++ {
		start := time.Now()
		resp, err := client.Get(testURL)
		if err != nil {
			if i == 0 {
				res.Error = shortError(err)
				return res
			}
			break
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		delay = int(time.Since(start).Milliseconds())
	}
	res.OK, res.DelayMs = true, delay

	if speed {
		ctx, cancel := context.WithTimeout(context.Background(), outboundSpeedDuration+outboundProbeTimeout)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, outboundSpeedURL, nil)
		client.Timeout = 0
		resp, err := client.Do(req)
		if err != nil {
			res.Error = "speed test: " + shortError(err)
			return res
		}
		defer resp.Body.Close()
		start := time.Now()
		var total int64
		buf := make([]byte, 64<<10)
		for time.Since(start) < outboundSpeedDuration {
			n, err := resp.Body.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		if secs := time.Since(start).Seconds(); secs > 0 {
			res.SpeedKBps = int(float64(total) / 1024 / secs)
		}
	}
	return res
}

// probeClient is an HTTP client whose requests leave through an outbound of
// the running Xray.
func probeClient(tag string) (*http.Client, error) {
	if !slices.Contains(ProbeableOutbounds(), tag) {
		return nil, errors.New("not in the running Xray: save the outbounds first")
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", outboundProbePort),
			User: url.UserPassword(OutboundProbeUser+tag, outboundProbePassword)}),
		MaxIdleConnsPerHost: 1,
	}
	return &http.Client{Transport: transport, Timeout: outboundProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func shortError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}

// ProbeAllOutbounds tests every outbound of the running Xray, a few at a time.
func ProbeAllOutbounds(testURL string) []*OutboundProbeResult {
	tags := ProbeableOutbounds()
	results := make([]*OutboundProbeResult, len(tags))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, tag := range tags {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = ProbeOutbound(tag, testURL, false)
		}()
	}
	wg.Wait()
	return results
}
