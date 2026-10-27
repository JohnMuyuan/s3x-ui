package job

import (
	"net/netip"
	"strings"

	"x-ui/logger"
	"x-ui/web/service"
)

// ipLimitAllowlist holds the addresses the IP limit leaves alone: they are not
// counted towards a client's limit and so never banned, which keeps a client
// sharing an office or carrier NAT with others from being cut off.
type ipLimitAllowlist []netip.Prefix

// parseIpLimitAllowlist reads comma or newline separated CIDRs and addresses.
func parseIpLimitAllowlist(raw string) (ipLimitAllowlist, error) {
	var list ipLimitAllowlist
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			addr, aerr := netip.ParseAddr(field)
			if aerr != nil {
				return nil, err
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		// an IPv4-mapped prefix would never contain the unmapped addresses checked
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		list = append(list, prefix.Masked())
	}
	return list, nil
}

func loadIpLimitAllowlist() ipLimitAllowlist {
	raw, err := (&service.SettingService{}).GetIpLimitAllowlist()
	if err != nil {
		return nil
	}
	list, err := parseIpLimitAllowlist(raw)
	if err != nil {
		logger.Warning("[LimitIP] ignoring the IP limit allowlist:", err)
		return nil
	}
	return list
}

func (l ipLimitAllowlist) contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range l {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// limited is ips without the allowlisted ones, in the same order.
func (l ipLimitAllowlist) limited(ips []string) []string {
	if len(l) == 0 {
		return ips
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !l.contains(ip) {
			out = append(out, ip)
		}
	}
	return out
}
