package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"x-ui/logger"
	"x-ui/util/json_util"
	"x-ui/util/random"
	"x-ui/xray"

	"golang.org/x/net/proxy"
)

// The panel's own requests (Telegram, GitHub downloads, the WARP API, external
// subscriptions) can leave through an Xray outbound or balancer, for a server
// whose direct route to them is blocked or slow. They enter Xray through a
// loopback SOCKS inbound that a routing rule sends to the chosen target.
const (
	PanelEgressTag = "panel-egress"
	// next to Xray's API (62789), sbcore's API and bridge (62790, 62791) and
	// the outbound tests (62793)
	panelEgressPort = 62792
	panelEgressUser = "panel"
)

var panelEgressPassword = random.Seq(24)

// injectPanelEgress adds the bridge when target names an outbound or balancer
// of cfg; otherwise the panel goes on connecting directly.
func injectPanelEgress(cfg *xray.Config, target string) {
	routing := map[string]any{}
	if len(cfg.RouterConfig) > 0 && json.Unmarshal(cfg.RouterConfig, &routing) != nil {
		logger.Warning("panel egress: the routing section does not parse, connecting directly")
		return
	}
	rule := map[string]any{"type": "field", "inboundTag": []string{PanelEgressTag}}
	switch {
	case hasTag(cfg.OutboundConfigs, target):
		rule["outboundTag"] = target
	case hasTag(mustMarshal(routing["balancers"]), target):
		rule["balancerTag"] = target
	default:
		logger.Warningf("panel egress: no outbound or balancer %q, connecting directly", target)
		return
	}
	rules, _ := routing["rules"].([]any)
	routing["rules"] = append([]any{rule}, rules...)
	raw, err := json.Marshal(routing)
	if err != nil {
		return
	}
	settings, _ := json.Marshal(map[string]any{
		"auth":     "password",
		"accounts": []map[string]string{{"user": panelEgressUser, "pass": panelEgressPassword}},
		"udp":      false,
	})
	cfg.RouterConfig = raw
	cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     panelEgressPort,
		Protocol: "socks",
		Settings: settings,
		Tag:      PanelEgressTag,
	})
}

func hasTag(list json_util.RawMessage, tag string) bool {
	var items []struct {
		Tag string `json:"tag"`
	}
	json.Unmarshal(list, &items)
	for _, item := range items {
		if item.Tag == tag {
			return true
		}
	}
	return false
}

func mustMarshal(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

// PanelProxyURL is the bridge's SOCKS URL while the running Xray has it, or ""
// to connect directly.
func PanelProxyURL() string {
	if p == nil || !p.IsRunning() {
		return ""
	}
	for _, ib := range p.GetConfig().InboundConfigs {
		if ib.Tag == PanelEgressTag {
			return fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", panelEgressUser, panelEgressPassword, panelEgressPort)
		}
	}
	return ""
}

// PanelDial connects the way the panel's own requests should: through the
// bridge when there is one, decided per connection, since Xray comes and goes.
func PanelDial(ctx context.Context, network, addr string) (net.Conn, error) {
	direct := &net.Dialer{Timeout: 10 * time.Second}
	proxyURL := PanelProxyURL()
	if proxyURL == "" {
		return direct.DialContext(ctx, network, addr)
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	dialer, err := proxy.FromURL(u, direct)
	if err != nil {
		return nil, err
	}
	return dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
}

// PanelHTTPClient is an HTTP client for the panel's own requests.
func PanelHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = PanelDial
	return &http.Client{Timeout: timeout, Transport: transport}
}
