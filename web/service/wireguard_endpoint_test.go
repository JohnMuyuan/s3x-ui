package service

import (
	"strings"
	"testing"
)

func TestPinWireguardEndpointFamily(t *testing.T) {
	defer func(f func() string) { reachableFamily = f }(reachableFamily)
	reachableFamily = func() string { return "UseIPv4" }
	in := `[{"tag":"direct","protocol":"freedom"},` +
		`{"tag":"warp","protocol":"wireguard","settings":{"peers":[{"endpoint":"engage.cloudflareclient.com:2408"}]}},` +
		`{"tag":"wg-ip","protocol":"wireguard","settings":{"peers":[{"endpoint":"162.159.192.1:2408"}]}},` +
		`{"tag":"wg-own","protocol":"wireguard","settings":{"peers":[{"endpoint":"a.example:51820"}]},"streamSettings":{"sockopt":{"domainStrategy":"UseIPv6"}}}]`
	out := string(pinWireguardEndpointFamily([]byte(in)))
	if strings.Count(out, `"domainStrategy":"UseIPv4"`) != 1 || !strings.Contains(out, `"domainStrategy":"UseIPv6"`) {
		t.Errorf("only the named endpoint without a choice gets the family:\n%s", out)
	}
	reachableFamily = func() string { return "any" }
	if out := string(pinWireguardEndpointFamily([]byte(in))); out != in {
		t.Errorf("a dual-stack server changed the outbounds:\n%s", out)
	}
}
