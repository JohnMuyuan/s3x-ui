package service

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"

	"x-ui/logger"
	"x-ui/util/json_util"
)

// dropPlaintextOutbounds leaves out the VLESS and Trojan outbounds Xray 26
// refuses: with no TLS or REALITY (and, for VLESS, no VLESS encryption) to a
// public address. Xray rejects the whole config for one of them, which takes
// every inbound down; without them it starts, and the warning names each.
// The checks follow Xray's own (infra/conf validateOutboundTransportSecurity).
func dropPlaintextOutbounds(outbounds json_util.RawMessage) json_util.RawMessage {
	if len(outbounds) == 0 {
		return outbounds
	}
	var list []map[string]any
	if err := json.Unmarshal(outbounds, &list); err != nil {
		return outbounds
	}
	kept := list[:0]
	for _, ob := range list {
		if plaintextToPublic(ob) {
			logger.Warningf("outbound %v is left out: Xray refuses %v without TLS or REALITY to a public address; turn on TLS or REALITY for it", ob["tag"], ob["protocol"])
			continue
		}
		kept = append(kept, ob)
	}
	if len(kept) == len(list) {
		return outbounds
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return outbounds
	}
	return out
}

func plaintextToPublic(ob map[string]any) bool {
	stream, _ := ob["streamSettings"].(map[string]any)
	if security, _ := stream["security"].(string); security != "" && security != "none" {
		return false
	}
	settings, _ := ob["settings"].(map[string]any)
	var address string
	switch ob["protocol"] {
	case "vless":
		address, _ = settings["address"].(string)
		encryption, _ := settings["encryption"].(string)
		if vnext, _ := settings["vnext"].([]any); len(vnext) > 0 {
			server, _ := vnext[0].(map[string]any)
			address, _ = server["address"].(string)
			if users, _ := server["users"].([]any); len(users) > 0 {
				user, _ := users[0].(map[string]any)
				encryption, _ = user["encryption"].(string)
			}
		}
		if encryption != "" && encryption != "none" {
			return false
		}
	case "trojan":
		address, _ = settings["address"].(string)
		if servers, _ := settings["servers"].([]any); len(servers) > 0 {
			server, _ := servers[0].(map[string]any)
			address, _ = server["address"].(string)
		}
	default:
		return false
	}
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
