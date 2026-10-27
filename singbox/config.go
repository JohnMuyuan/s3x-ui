package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"x-ui/database/model"
)

// Egress modes for traffic leaving sbcore.
const (
	EgressXray   = "xray"
	EgressDirect = "direct"
)

const (
	bridgeOutboundTag = "xray-bridge"
	// BridgeTag is the Xray inbound receiving sbcore's egress.
	BridgeTag = "sbcore-bridge"
)

// optionKeys whitelists the settings keys passed through to sing-box per
// protocol; sing-box rejects unknown fields, so UI-only keys must not leak.
var optionKeys = map[model.Protocol][]string{
	model.AnyTLS:    {"padding_scheme"},
	model.Hysteria2: {"up_mbps", "down_mbps", "obfs", "ignore_client_bandwidth", "masquerade", "bbr_profile"},
	model.Hysteria:  {"up_mbps", "down_mbps", "obfs"},
	model.TUIC:      {"congestion_control", "auth_timeout", "zero_rtt_handshake", "heartbeat"},
	model.Naive:     {"network", "quic_congestion_control"},
	model.ShadowTLS: {"version", "handshake", "strict_mode"},
	model.Snell:     {"version", "psk", "obfs_mode", "mode"},
}

var quicProtocols = map[model.Protocol]bool{model.Hysteria: true, model.Hysteria2: true, model.TUIC: true}

var tlsRequired = map[model.Protocol]bool{
	model.AnyTLS: true, model.Hysteria: true, model.Hysteria2: true, model.TUIC: true, model.Naive: true,
}

// BuildInbounds converts one panel inbound into sing-box inbounds: one, or two
// for ShadowTLS, whose inner Shadowsocks inbound only listens on loopback.
func BuildInbounds(ib *model.Inbound) ([]map[string]any, error) {
	if !ib.Protocol.IsSingbox() {
		return nil, fmt.Errorf("inbound %q: %s is not a sing-box protocol", ib.Tag, ib.Protocol)
	}
	settings := map[string]any{}
	if ib.Settings != "" {
		if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
			return nil, fmt.Errorf("inbound %q: settings: %w", ib.Tag, err)
		}
	}
	out := map[string]any{
		"type":        string(ib.Protocol),
		"tag":         ib.Tag,
		"listen":      listenAddr(ib.Listen),
		"listen_port": ib.Port,
	}
	for _, key := range optionKeys[ib.Protocol] {
		if v, ok := settings[key]; ok && !isEmpty(v) {
			out[key] = v
		}
	}
	dropEmptyObfs(ib.Protocol, out)
	out["users"] = buildUsers(ib, settings)

	if tlsRequired[ib.Protocol] {
		tls, err := buildTLS(ib)
		if err != nil {
			return nil, fmt.Errorf("inbound %q: %w", ib.Tag, err)
		}
		out["tls"] = tls
	}

	if ib.Protocol == model.ShadowTLS {
		return buildShadowTLS(ib, settings, out)
	}
	return []map[string]any{out}, nil
}

func listenAddr(listen string) string {
	if listen == "" || listen == "0.0.0.0" {
		return "::"
	}
	return listen
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// dropEmptyObfs removes an obfs block whose password was left blank in the UI.
func dropEmptyObfs(p model.Protocol, out map[string]any) {
	if p != model.Hysteria2 {
		return
	}
	if obfs, ok := out["obfs"].(map[string]any); ok {
		if pw, _ := obfs["password"].(string); pw == "" {
			delete(out, "obfs")
		}
	}
}

// buildUsers keeps only clients that are enabled both in settings and in
// their traffic row; the user name is the email so stats map back to it.
func buildUsers(ib *model.Inbound, settings map[string]any) []map[string]any {
	disabled := map[string]bool{}
	for _, st := range ib.ClientStats {
		if !st.Enable {
			disabled[st.Email] = true
		}
	}
	clients, _ := settings["clients"].([]any)
	users := make([]map[string]any, 0, len(clients))
	for _, raw := range clients {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		email, _ := c["email"].(string)
		if email == "" || disabled[email] {
			continue
		}
		if enable, ok := c["enable"].(bool); ok && !enable {
			continue
		}
		password, _ := c["password"].(string)
		id, _ := c["id"].(string)
		switch ib.Protocol {
		case model.Hysteria:
			users = append(users, map[string]any{"name": email, "auth_str": password})
		case model.TUIC:
			users = append(users, map[string]any{"name": email, "uuid": id, "password": password})
		case model.Naive:
			users = append(users, map[string]any{"username": email, "password": password})
		case model.Snell:
			users = append(users, map[string]any{"name": email, "userkey": password})
		default:
			users = append(users, map[string]any{"name": email, "password": password})
		}
	}
	return users
}

// buildTLS maps the panel's Xray-style TLS/REALITY settings to sing-box's.
func buildTLS(ib *model.Inbound) (map[string]any, error) {
	stream := map[string]any{}
	if ib.StreamSettings != "" {
		if err := json.Unmarshal([]byte(ib.StreamSettings), &stream); err != nil {
			return nil, fmt.Errorf("stream settings: %w", err)
		}
	}
	security, _ := stream["security"].(string)
	switch security {
	case "tls":
		return buildCertTLS(ib.Protocol, stream)
	case "reality":
		if quicProtocols[ib.Protocol] {
			return nil, fmt.Errorf("%s cannot use REALITY", ib.Protocol)
		}
		return buildRealityTLS(stream)
	}
	return nil, fmt.Errorf("%s requires TLS", ib.Protocol)
}

func buildCertTLS(p model.Protocol, stream map[string]any) (map[string]any, error) {
	ts, _ := stream["tlsSettings"].(map[string]any)
	tls := map[string]any{"enabled": true}
	if sn, _ := ts["serverName"].(string); sn != "" {
		tls["server_name"] = sn
	}
	if v, _ := ts["minVersion"].(string); v != "" {
		tls["min_version"] = v
	}
	if v, _ := ts["maxVersion"].(string); v != "" {
		tls["max_version"] = v
	}
	if alpn := filterALPN(p, ts["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	certs, _ := ts["certificates"].([]any)
	if len(certs) == 0 {
		return nil, fmt.Errorf("TLS needs a certificate")
	}
	cert, _ := certs[0].(map[string]any)
	certFile, _ := cert["certificateFile"].(string)
	keyFile, _ := cert["keyFile"].(string)
	switch {
	case certFile != "" && keyFile != "":
		tls["certificate_path"] = certFile
		tls["key_path"] = keyFile
	case !isEmpty(cert["certificate"]) && !isEmpty(cert["key"]):
		tls["certificate"] = cert["certificate"]
		tls["key"] = cert["key"]
	default:
		return nil, fmt.Errorf("TLS certificate is empty")
	}
	return tls, nil
}

// filterALPN drops HTTP/1.1 and h2 for QUIC protocols, whose clients only
// offer h3 or their own ALPN; an empty result lets sing-box pick its default.
func filterALPN(p model.Protocol, raw any) []string {
	list, _ := raw.([]any)
	var alpn []string
	for _, v := range list {
		s, _ := v.(string)
		if s == "" || (quicProtocols[p] && (s == "h2" || s == "http/1.1")) {
			continue
		}
		alpn = append(alpn, s)
	}
	return alpn
}

func buildRealityTLS(stream map[string]any) (map[string]any, error) {
	rs, _ := stream["realitySettings"].(map[string]any)
	dest, _ := rs["dest"].(string)
	if dest == "" {
		dest, _ = rs["target"].(string)
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, fmt.Errorf("REALITY target %q: %w", dest, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("REALITY target port %q: %w", portStr, err)
	}
	privateKey, _ := rs["privateKey"].(string)
	if privateKey == "" {
		return nil, fmt.Errorf("REALITY private key is empty")
	}
	names := toList(rs["serverNames"])
	reality := map[string]any{
		"enabled":     true,
		"handshake":   map[string]any{"server": host, "server_port": port},
		"private_key": privateKey,
		"short_id":    toList(rs["shortIds"]),
	}
	if ms, ok := rs["maxTimediff"].(float64); ok && ms > 0 {
		reality["max_time_difference"] = fmt.Sprintf("%dms", int64(ms))
	}
	tls := map[string]any{"enabled": true, "reality": reality}
	if len(names) > 0 {
		tls["server_name"] = names[0]
	}
	return tls, nil
}

func toList(raw any) []string {
	var out []string
	switch t := raw.(type) {
	case []any:
		for _, v := range t {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		for _, s := range strings.Split(t, ",") {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// buildShadowTLS chains the ShadowTLS v3 front to a loopback Shadowsocks
// inbound holding the inner cipher, configured under settings.shadowsocks.
func buildShadowTLS(ib *model.Inbound, settings map[string]any, front map[string]any) ([]map[string]any, error) {
	ss, _ := settings["shadowsocks"].(map[string]any)
	method, _ := ss["method"].(string)
	password, _ := ss["password"].(string)
	if method == "" || password == "" {
		return nil, fmt.Errorf("inbound %q: ShadowTLS needs an inner Shadowsocks method and password", ib.Tag)
	}
	if _, ok := front["version"]; !ok {
		front["version"] = 3
	}
	innerTag := ib.Tag + "-ss"
	front["detour"] = innerTag
	inner := map[string]any{
		"type":        "shadowsocks",
		"tag":         innerTag,
		"listen":      "127.0.0.1",
		"listen_port": 0,
		"method":      method,
		"password":    password,
	}
	return []map[string]any{front, inner}, nil
}

// BuildConfig assembles the full sbcore config around the given inbounds.
func BuildConfig(inbounds []map[string]any, egress string, logLevel string) map[string]any {
	final := bridgeOutboundTag
	if egress == EgressDirect {
		final = "direct"
	}
	if inbounds == nil {
		inbounds = []map[string]any{}
	}
	return map[string]any{
		"log":      map[string]any{"level": logLevel, "timestamp": false},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{
				"type": "socks", "tag": bridgeOutboundTag, "version": "5",
				"server": "127.0.0.1", "server_port": BridgePort,
				"username": BridgeUser, "password": BridgePassword,
			},
			{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": final},
	}
}

// BridgeInbound is the Xray inbound that receives sbcore's egress traffic.
func BridgeInbound() map[string]any {
	return map[string]any{
		"tag":      BridgeTag,
		"listen":   "127.0.0.1",
		"port":     BridgePort,
		"protocol": "socks",
		"settings": map[string]any{
			"auth":     "password",
			"accounts": []map[string]any{{"user": BridgeUser, "pass": BridgePassword}},
			"udp":      true,
			"ip":       "127.0.0.1",
		},
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
	}
}
