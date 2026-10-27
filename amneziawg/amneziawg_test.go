package amneziawg

import (
	"strings"
	"testing"

	"x-ui/database/model"
	"x-ui/xray"
)

const (
	keyA = "4CfHsm1fTpGQ5Lnfye3oK0eIAq0HYCbUlmcGv6ALe1o=" // any 32 bytes do
	keyB = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

func inbound(settings string) *model.Inbound {
	return &model.Inbound{Id: 9, Tag: "sb-inbound-51820", Port: 51820, Enable: true, Protocol: model.AmneziaWG, Settings: settings,
		ClientStats: []xray.ClientTraffic{{Email: "quota", Enable: false}}}
}

const params = `"jc":4,"jmin":40,"jmax":70,"s1":20,"s2":30,"h1":11,"h2":22,"h3":33,"h4":44`

func TestFromInbound(t *testing.T) {
	inst, problems, ok := FromInbound(inbound(`{"secretKey":"` + keyA + `","address":"10.66.66.1/24",` + params + `,"clients":[
		{"email":"a","publicKey":"` + keyB + `","address":"10.66.66.2/32","enable":true},
		{"email":"off","publicKey":"` + keyB + `","address":"10.66.66.3/32","enable":false},
		{"email":"quota","publicKey":"` + keyB + `","address":"10.66.66.4/32","enable":true},
		{"email":"clash","publicKey":"` + keyB + `","address":"10.66.66.2/32","enable":true},
		{"email":"outside","publicKey":"` + keyB + `","address":"10.9.9.9/32","enable":true}]}`))
	if !ok || len(inst.Peers) != 1 || inst.Peers[0].Email != "a" {
		t.Fatalf("peers = %+v, want only a", inst.Peers)
	}
	if len(problems) != 2 {
		t.Errorf("problems = %v, want the clashing and the outside address", problems)
	}
	if inst.Iface != "awg9" || inst.MTU != 1420 {
		t.Errorf("iface %s mtu %d", inst.Iface, inst.MTU)
	}
	conf := inst.deviceConfig()
	for _, want := range []string{"listen_port=51820\n", "jc=4\n", "s2=30\n", "h4=44\n", "private_key=e027c7b2"} {
		if !strings.Contains(conf, want) {
			t.Errorf("device config lacks %q:\n%s", want, conf)
		}
	}
}

func TestParamsRefused(t *testing.T) {
	for name, p := range map[string]string{
		"same handshake sizes": `"jc":4,"jmin":40,"jmax":70,"s1":20,"s2":76,"h1":11,"h2":22,"h3":33,"h4":44`,
		"repeated header":      `"jc":4,"jmin":40,"jmax":70,"s1":20,"s2":30,"h1":11,"h2":11,"h3":33,"h4":44`,
		"standard header":      `"jc":4,"jmin":40,"jmax":70,"s1":20,"s2":30,"h1":1,"h2":22,"h3":33,"h4":44`,
		"jmin above jmax":      `"jc":4,"jmin":80,"jmax":70,"s1":20,"s2":30,"h1":11,"h2":22,"h3":33,"h4":44`,
	} {
		_, _, ok := FromInbound(inbound(`{"secretKey":"` + keyA + `","address":"10.66.66.1/24",` + p + `,"clients":[
			{"email":"a","publicKey":"` + keyB + `","address":"10.66.66.2/32","enable":true}]}`))
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPeersDiff(t *testing.T) {
	a := Peer{PublicKey: "aa", Email: "a"}
	b := Peer{PublicKey: "bb", Email: "b"}
	applied := map[string]string{"aa": a.config(), "cc": "x"}
	diff := peersDiff(applied, []Peer{a, b})
	if strings.Contains(diff, "public_key=aa") {
		t.Error("an unchanged peer was resent")
	}
	if !strings.Contains(diff, "public_key=bb\n") || !strings.Contains(diff, "public_key=cc\nremove=true\n") {
		t.Errorf("diff misses the new or the removed peer:\n%s", diff)
	}
}

func TestParseStats(t *testing.T) {
	got := parseStats("private_key=x\nlisten_port=1\npublic_key=aa\nrx_bytes=10\ntx_bytes=20\npublic_key=bb\nrx_bytes=1\ntx_bytes=2\nerrno=0\n")
	if got["aa"] != (counters{10, 20}) || got["bb"] != (counters{1, 2}) {
		t.Errorf("stats = %v", got)
	}
}
