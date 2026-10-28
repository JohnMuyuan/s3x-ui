package service

import (
	"encoding/json"
	"testing"
)

func TestDropPlaintextOutbounds(t *testing.T) {
	in := `[
		{"tag":"direct","protocol":"freedom"},
		{"tag":"plain-vnext","protocol":"vless","settings":{"vnext":[{"address":"sg.example.com","port":80,"users":[{"id":"x","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"none"}},
		{"tag":"plain-flat","protocol":"vless","settings":{"address":"1.2.3.4","port":80,"id":"x","encryption":"none"}},
		{"tag":"tls","protocol":"vless","settings":{"vnext":[{"address":"sg.example.com","port":443,"users":[{"id":"x"}]}]},"streamSettings":{"security":"tls"}},
		{"tag":"reality","protocol":"vless","settings":{"address":"1.2.3.4","port":443,"id":"x"},"streamSettings":{"security":"reality"}},
		{"tag":"vless-enc","protocol":"vless","settings":{"address":"1.2.3.4","port":80,"id":"x","encryption":"mlkem768x25519plus.native.0rtt.abc"}},
		{"tag":"lan-ip","protocol":"vless","settings":{"address":"192.168.1.2","port":80,"id":"x"}},
		{"tag":"lan-name","protocol":"vless","settings":{"address":"nas.lan","port":80,"id":"x"}},
		{"tag":"dotless","protocol":"vless","settings":{"address":"backend","port":80,"id":"x"}},
		{"tag":"trojan-plain","protocol":"trojan","settings":{"servers":[{"address":"tj.example.com","port":80,"password":"p"}]}},
		{"tag":"trojan-tls","protocol":"trojan","settings":{"servers":[{"address":"tj.example.com","port":443,"password":"p"}]},"streamSettings":{"security":"tls"}},
		{"tag":"ss","protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":8388}]}}
	]`
	var kept []struct{ Tag string }
	if err := json.Unmarshal(dropPlaintextOutbounds([]byte(in)), &kept); err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, ob := range kept {
		tags = append(tags, ob.Tag)
	}
	raw, _ := json.Marshal(tags)
	if want := `["direct","tls","reality","vless-enc","lan-ip","lan-name","dotless","trojan-tls","ss"]`; string(raw) != want {
		t.Errorf("kept %s\nwant %s", raw, want)
	}
	// nothing to drop: the outbounds come back untouched
	same := `[{"tag":"direct","protocol":"freedom"}]`
	if got := string(dropPlaintextOutbounds([]byte(same))); got != same {
		t.Errorf("rewrote %s", got)
	}
}
