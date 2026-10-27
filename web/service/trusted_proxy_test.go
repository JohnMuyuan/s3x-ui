package service

import (
	"path/filepath"
	"testing"

	"x-ui/database"
)

func TestClientIP(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Skip("no database:", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := database.GetDB().DB(); err == nil {
			sqlDB.Close()
		}
	})
	var s SettingService
	cases := []struct {
		trusted, remote, realIP, xff, want string
	}{
		// the default trusts a proxy on this machine
		{"", "127.0.0.1:5000", "", "203.0.113.9", "203.0.113.9"},
		{"", "[::1]:5000", "203.0.113.9", "", "203.0.113.9"},
		// anyone else gets their own address, whatever they claim
		{"", "198.51.100.7:5000", "203.0.113.9", "203.0.113.9", "198.51.100.7"},
		// a client's own X-Forwarded-For entries come first; the proxy's last
		{"10.0.0.0/8", "10.0.0.2:80", "", "1.1.1.1, 203.0.113.9, 10.0.0.1", "203.0.113.9"},
		{"10.0.0.0/8", "10.0.0.2:80", "", "garbage, 203.0.113.9", "203.0.113.9"},
		{"10.0.0.0/8", "10.0.0.2:80", "203.0.113.5", "", "203.0.113.5"},
		{"10.0.0.0/8", "127.0.0.1:80", "203.0.113.5", "", "127.0.0.1"},
		{"192.0.2.4", "192.0.2.4:80", "", "2001:db8::1", "2001:db8::1"},
		{"192.0.2.4", "[::ffff:192.0.2.4]:80", "", "203.0.113.1", "203.0.113.1"},
	}
	for _, tc := range cases {
		trusted := tc.trusted
		if trusted == "" {
			trusted = DefaultTrustedProxyCIDRs
		}
		s.setString("trustedProxyCIDRs", trusted)
		if got := s.ClientIP(tc.remote, tc.realIP, tc.xff); got != tc.want {
			t.Errorf("trusting %s, %s with X-Real-IP %q X-Forwarded-For %q: %s, want %s", trusted, tc.remote, tc.realIP, tc.xff, got, tc.want)
		}
	}
	if _, err := ParseTrustedProxies("10.0.0.0/8, 192.0.2.1, ::1/128"); err != nil {
		t.Error(err)
	}
	if _, err := ParseTrustedProxies("10.0.0.0/8, nginx"); err == nil {
		t.Error("nginx parsed")
	}
}
