package service

import (
	"net/netip"
	"testing"
)

func TestRealityScanRefusesPrivate(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "fe80::1", "::ffff:172.16.0.1"} {
		if !privateAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s counted as public", a)
		}
	}
	if privateAddr(netip.MustParseAddr("104.16.124.96")) {
		t.Error("a public address counted as private")
	}
	var s ServerService
	for _, r := range s.ScanRealityTargets("127.0.0.1:443, localhost, 10.0.0.0/30, example.invalid, host:99999") {
		if r.Feasible || r.Reason == "" {
			t.Errorf("%s: %+v", r.Target, r)
		}
	}
}
