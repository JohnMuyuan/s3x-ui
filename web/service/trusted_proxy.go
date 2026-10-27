package service

import (
	"net"
	"net/netip"
	"strings"

	"x-ui/util/common"
)

// DefaultTrustedProxyCIDRs trusts a reverse proxy on the same machine.
const DefaultTrustedProxyCIDRs = "127.0.0.1/32,::1/128"

// ParseTrustedProxies reads a comma separated list of CIDRs and single IPs.
func ParseTrustedProxies(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, common.NewError("not an IP or CIDR: ", entry)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func (s *SettingService) GetTrustedProxyCIDRs() (string, error) {
	return s.getString("trustedProxyCIDRs")
}

// ViaTrustedProxy reports whether a request from remoteAddr (an IP, or
// host:port) came through one of the trusted proxies, so its X-Real-IP,
// X-Forwarded-For and X-Forwarded-Host headers may be believed.
func (s *SettingService) ViaTrustedProxy(remoteAddr string) bool {
	addr, ok := parseAddr(remoteAddr)
	if !ok {
		return false
	}
	return s.isTrustedProxy(addr)
}

func (s *SettingService) isTrustedProxy(addr netip.Addr) bool {
	value, err := s.GetTrustedProxyCIDRs()
	if err != nil {
		value = DefaultTrustedProxyCIDRs
	}
	prefixes, _ := ParseTrustedProxies(value)
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP is the address a request came from. Behind a trusted proxy it is
// the client the proxy forwarded: X-Forwarded-For read from the right,
// skipping trusted hops (whatever a client puts at the left is its own
// claim), else X-Real-IP. Anything else gets its own peer address, whatever
// headers it sends.
func (s *SettingService) ClientIP(remoteAddr, realIP, forwardedFor string) string {
	peer, ok := parseAddr(remoteAddr)
	if !ok {
		return remoteAddr
	}
	if !s.isTrustedProxy(peer) {
		return peer.String()
	}
	if forwardedFor != "" {
		hops := strings.Split(forwardedFor, ",")
		client := netip.Addr{}
		for i := len(hops) - 1; i >= 0; i-- {
			hop, ok := parseAddr(hops[i])
			if !ok {
				break
			}
			client = hop
			if !s.isTrustedProxy(hop) {
				break
			}
		}
		if client.IsValid() {
			return client.String()
		}
	}
	if addr, ok := parseAddr(realIP); ok {
		return addr.String()
	}
	return peer.String()
}

func parseAddr(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	addr, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
