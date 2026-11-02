package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"x-ui/logger"
	"x-ui/util/json_util"
)

// plaintextDialTag prefixes the freedom outbounds that dial plaintext servers.
const plaintextDialTag = "s3x-plain-dial-"

// transportHost is where each transport names the host it asks for. Left
// empty it would ask for the private address such an outbound is given.
var transportHost = map[string][2]string{
	"ws":          {"wsSettings", "host"},
	"httpupgrade": {"httpupgradeSettings", "host"},
	"xhttp":       {"xhttpSettings", "host"},
	"splithttp":   {"splithttpSettings", "host"},
	"grpc":        {"grpcSettings", "authority"},
}

// keepPlaintextOutbounds keeps running the VLESS and Trojan outbounds Xray 26
// refuses: with no TLS or REALITY (and, for VLESS, no VLESS encryption) to a
// public address. Xray rejects the whole config for one of them, and leaving
// one out closes every connection routed to it. The warning names each.
func keepPlaintextOutbounds(outbounds json_util.RawMessage) json_util.RawMessage {
	out, tags := redirectPlaintextOutbounds(outbounds)
	for _, tag := range tags {
		logger.Warningf("outbound %v has no TLS or REALITY: its traffic can be read on the way to the server", tag)
	}
	return out
}

// redirectPlaintextOutbounds gives such outbounds the private address Xray
// asks for, and has a freedom outbound they dial through connect to the real
// one. The checks follow Xray's own (infra/conf
// validateOutboundTransportSecurity).
func redirectPlaintextOutbounds(outbounds json_util.RawMessage) (json_util.RawMessage, []any) {
	if len(outbounds) == 0 {
		return outbounds, nil
	}
	var list []map[string]any
	if err := json.Unmarshal(outbounds, &list); err != nil {
		return outbounds, nil
	}
	var tags []any
	for i, ob := range list {
		if plaintextToPublic(ob) {
			list = append(list, redirectPlaintext(ob, plaintextDialTag+strconv.Itoa(i)))
			tags = append(tags, ob["tag"])
		}
	}
	if len(tags) == 0 {
		return outbounds, nil
	}
	out, err := json.Marshal(list)
	if err != nil {
		return outbounds, nil
	}
	return out, tags
}

// redirectPlaintext returns the outbound that makes ob's connections. What
// shapes that connection (sockopt, including a dialerProxy chain, and the
// source address) moves there with it.
func redirectPlaintext(ob map[string]any, tag string) map[string]any {
	server := outboundServer(ob)
	address, _ := server["address"].(string)
	address = strings.Trim(address, "[]")
	port := fmt.Sprint(server["port"])
	stream, _ := ob["streamSettings"].(map[string]any)
	if stream == nil {
		stream = map[string]any{}
		ob["streamSettings"] = stream
	}
	keepTransportHost(stream, address, port)
	dial := map[string]any{
		"tag":      tag,
		"protocol": "freedom",
		"settings": map[string]any{"redirect": net.JoinHostPort(address, port)},
	}
	if sockopt, ok := stream["sockopt"]; ok {
		dial["streamSettings"] = map[string]any{"sockopt": sockopt}
	}
	for _, key := range []string{"sendThrough", "targetStrategy"} {
		if value, ok := ob[key]; ok {
			dial[key] = value
			delete(ob, key)
		}
	}
	stream["sockopt"] = map[string]any{"dialerProxy": tag}
	server["address"] = "127.0.0.1"
	return dial
}

func keepTransportHost(stream map[string]any, address, port string) {
	network, _ := stream["network"].(string)
	target, ok := transportHost[network]
	if !ok {
		return
	}
	section, _ := stream[target[0]].(map[string]any)
	if section == nil {
		section = map[string]any{}
		stream[target[0]] = section
	}
	if host, _ := section[target[1]].(string); host != "" {
		return
	}
	headers, _ := section["headers"].(map[string]any)
	for name := range headers {
		if strings.EqualFold(name, "host") {
			return
		}
	}
	if port != "80" {
		address = net.JoinHostPort(address, port)
	}
	section[target[1]] = address
}

// outboundServer is where a VLESS, VMess or Trojan outbound keeps its server:
// the first vnext or servers entry, or settings itself.
func outboundServer(ob map[string]any) map[string]any {
	settings, _ := ob["settings"].(map[string]any)
	for _, key := range []string{"vnext", "servers"} {
		if list, _ := settings[key].([]any); len(list) > 0 {
			server, _ := list[0].(map[string]any)
			return server
		}
	}
	return settings
}

func plaintextToPublic(ob map[string]any) bool {
	stream, _ := ob["streamSettings"].(map[string]any)
	if security, _ := stream["security"].(string); security != "" && security != "none" {
		return false
	}
	server := outboundServer(ob)
	switch ob["protocol"] {
	case "vless":
		encryption, _ := server["encryption"].(string)
		if users, _ := server["users"].([]any); len(users) > 0 {
			user, _ := users[0].(map[string]any)
			encryption, _ = user["encryption"].(string)
		}
		if encryption != "" && encryption != "none" {
			return false
		}
	case "trojan":
	default:
		return false
	}
	address, _ := server["address"].(string)
	return address != "" && !privateAddress(address)
}

// Xray's private ranges and domains (common/geodata/consts.go).
var (
	privatePrefixes = func() []netip.Prefix {
		var prefixes []netip.Prefix
		for _, p := range []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
			"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
			"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
			"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
		} {
			prefixes = append(prefixes, netip.MustParsePrefix(p))
		}
		return prefixes
	}()
	privateDomains = []string{"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal"}
	dotlessDomain  = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func privateAddress(address string) bool {
	if ip, err := netip.ParseAddr(strings.Trim(address, "[]")); err == nil {
		ip = ip.Unmap()
		for _, p := range privatePrefixes {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	domain := strings.TrimSuffix(strings.ToLower(address), ".")
	if dotlessDomain.MatchString(domain) {
		return true
	}
	for _, d := range privateDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
