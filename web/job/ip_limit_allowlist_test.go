package job

import (
	"slices"
	"testing"
)

func TestIpLimitAllowlist(t *testing.T) {
	list, err := parseIpLimitAllowlist(" 10.0.0.0/8, 203.0.113.7\n2001:db8::/32,::ffff:198.51.100.0/120 ")
	if err != nil {
		t.Fatal(err)
	}
	ips := []string{"10.1.2.3", "8.8.8.8", "203.0.113.7", "203.0.113.8", "2001:db8::1", "2001:db9::1", "198.51.100.9", "::ffff:10.9.9.9"}
	want := []string{"8.8.8.8", "203.0.113.8", "2001:db9::1"}
	if got := list.limited(ips); !slices.Equal(got, want) {
		t.Errorf("limited = %v, want %v", got, want)
	}
	if got := ipLimitAllowlist(nil).limited(ips); !slices.Equal(got, ips) {
		t.Errorf("an empty allowlist changed the list: %v", got)
	}
	for _, bad := range []string{"10.0.0.0/33", "example.com", "1.2.3"} {
		if _, err := parseIpLimitAllowlist(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
