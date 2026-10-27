package service

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeepCurrentWarp(t *testing.T) {
	tmpl := func(key string) string {
		return `{"log":{},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"warp","protocol":"wireguard","settings":{"mtu":1420,"secretKey":"` +
			key + `","address":["172.16.0.2/32"],"reserved":[1,2,3],"peers":[{"publicKey":"P` + key + `","endpoint":"e:2408"}]}}],"routing":{"rules":[{"domain":["regexp:a<b"]}]}}`
	}
	data := `{"private_key":"NEW","device_id":"d"}`
	// a page loaded before the rotation saves the old key: the current one stays
	got := keepCurrentWarp(tmpl("OLD"), tmpl("NEW"), data)
	if !strings.Contains(got, `"secretKey": "NEW"`) || !strings.Contains(got, `"publicKey": "PNEW"`) || strings.Contains(got, "OLD") {
		t.Errorf("stale key kept:\n%s", got)
	}
	if !strings.Contains(got, `regexp:a<b`) {
		t.Error("the template got HTML-escaped")
	}
	// the current key, or a WARP registered but not yet put in the outbound
	for _, c := range [][2]string{{"NEW", "NEW"}, {"OLD", "OLD"}} {
		if got := keepCurrentWarp(tmpl(c[0]), tmpl(c[1]), data); got != tmpl(c[0]) {
			t.Errorf("%v changed:\n%s", c, got)
		}
	}
	if got := keepCurrentWarp(tmpl("OLD"), tmpl("NEW"), ""); got != tmpl("OLD") {
		t.Error("changed without WARP data")
	}
}

func TestWireguardKeyPair(t *testing.T) {
	secret, public, err := wireguardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := base64.StdEncoding.DecodeString(secret)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	if base64.StdEncoding.EncodeToString(pub) != public || priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Errorf("bad key pair %s %s", secret, public)
	}
}
