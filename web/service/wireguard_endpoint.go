package service

import (
	"encoding/json"
	"net"
	"time"

	"x-ui/util/json_util"
)

// Xray picks one of the A and AAAA addresses of a WireGuard peer's endpoint
// name at random, so on a server with only IPv4 (or only IPv6) the tunnel
// comes up on some starts and not on others; WARP's engage.cloudflareclient.com
// has both. pinWireguardEndpointFamily has such outbounds resolve the family
// the server can reach, unless they choose one in sockopt.domainStrategy.
func pinWireguardEndpointFamily(outbounds json_util.RawMessage) json_util.RawMessage {
	var list []map[string]any
	if json.Unmarshal(outbounds, &list) != nil {
		return outbounds
	}
	strategy := ""
	changed := false
	for _, ob := range list {
		if ob["protocol"] != "wireguard" || !hasEndpointName(ob) {
			continue
		}
		stream, _ := ob["streamSettings"].(map[string]any)
		sockopt, _ := stream["sockopt"].(map[string]any)
		if s, _ := sockopt["domainStrategy"].(string); s != "" {
			continue
		}
		if strategy == "" {
			strategy = reachableFamily()
		}
		if strategy == "any" {
			return outbounds
		}
		if stream == nil {
			stream = map[string]any{}
			ob["streamSettings"] = stream
		}
		if sockopt == nil {
			sockopt = map[string]any{}
			stream["sockopt"] = sockopt
		}
		sockopt["domainStrategy"] = strategy
		changed = true
	}
	if !changed {
		return outbounds
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return outbounds
	}
	return raw
}

func hasEndpointName(ob map[string]any) bool {
	settings, _ := ob["settings"].(map[string]any)
	peers, _ := settings["peers"].([]any)
	for _, p := range peers {
		peer, _ := p.(map[string]any)
		endpoint, _ := peer["endpoint"].(string)
		if host, _, err := net.SplitHostPort(endpoint); err == nil && net.ParseIP(host) == nil {
			return true
		}
	}
	return false
}

var reachableFamily = func() string {
	// a UDP "connection" sends nothing; it fails without a route
	can := func(network, addr string) bool {
		c, err := net.DialTimeout(network, addr, time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	v4, v6 := can("udp4", "1.1.1.1:53"), can("udp6", "[2606:4700:4700::1111]:53")
	switch {
	case v4 && !v6:
		return "UseIPv4"
	case v6 && !v4:
		return "UseIPv6"
	}
	return "any"
}
