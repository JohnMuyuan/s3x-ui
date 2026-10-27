package mtproto

import (
	"strings"
	"testing"

	"x-ui/database/model"
	"x-ui/xray"
)

func TestFromInbound(t *testing.T) {
	ib := &model.Inbound{
		Id: 7, Tag: "sb-inbound-443", Port: 443, Enable: true, Protocol: model.MTProto,
		Settings: `{"fakeTlsDomain":"www.cloudflare.com","maxConnections":100,"clients":[
			{"email":"on","password":"00112233445566778899aabbccddeeff","enable":true},
			{"email":"off","password":"00112233445566778899aabbccddeeff","enable":false},
			{"email":"quota","password":"00112233445566778899aabbccddeeff","enable":true},
			{"email":"bad","password":"xyz","enable":true}]}`,
		ClientStats: []xray.ClientTraffic{{Email: "quota", Enable: false}},
	}
	inst, problems, ok := FromInbound(ib, "socks5://u:p@127.0.0.1:1")
	if !ok {
		t.Fatal("inbound not usable")
	}
	want := "ee00112233445566778899aabbccddeeff" + "7777772e636c6f7564666c6172652e636f6d"
	if len(inst.Secrets) != 1 || inst.Secrets[0] != (Secret{"on", want}) {
		t.Fatalf("secrets = %v, want only the enabled client", inst.Secrets)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "bad") {
		t.Errorf("problems = %v, want one about the bad key", problems)
	}

	conf := render(inst, 5555, "tok")
	for _, line := range []string{`bind-to = "0.0.0.0:443"`, `prefer-ip = "prefer-ipv4"`, `api-bind-to = "127.0.0.1:5555"`, `api-token = "tok"`,
		`proxies = ["socks5://u:p@127.0.0.1:1"]`, "max-connections = 100", `"on" = "` + want + `"`} {
		if !strings.Contains(conf, line) {
			t.Errorf("config lacks %s:\n%s", line, conf)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(conf), `"on" = "`+want+`"`) || strings.Index(conf, "[secrets]") < strings.Index(conf, "[throttle]") {
		t.Errorf("[secrets] must be the last table:\n%s", conf)
	}

	ib.Enable = false
	if _, _, ok := FromInbound(ib, ""); ok {
		t.Error("a disabled inbound must not run")
	}
}
