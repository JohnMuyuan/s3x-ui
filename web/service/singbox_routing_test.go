package service

import (
	"encoding/json"
	"testing"

	"x-ui/database/model"
)

func TestRouteBridgedInbounds(t *testing.T) {
	clients := func(emails ...string) string {
		var list []map[string]any
		for _, e := range emails {
			list = append(list, map[string]any{"email": e})
		}
		raw, _ := json.Marshal(map[string]any{"clients": list})
		return string(raw)
	}
	users := bridgeUsers([]*model.Inbound{
		{Tag: "sb-inbound-14758", Protocol: model.Hysteria2, Enable: true, Settings: clients("hy-a", "hy-b")},
		{Tag: "sb-inbound-443", Protocol: model.ShadowTLS, Enable: true, Settings: clients("stls-a")},
		{Tag: "sb-inbound-8443", Protocol: model.MTProto, Enable: true, Settings: clients("mt-a")},
		{Tag: "sb-inbound-9", Protocol: model.TUIC, Enable: false, Settings: clients("off-a")},
		{Tag: "inbound-1080", Protocol: model.VLESS, Enable: true, Settings: clients("vl-a")},
	})
	router := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api"],"outboundTag":"api"},
		{"type":"field","inboundTag":["sb-inbound-14758"],"outboundTag":"ss-out"},
		{"type":"field","inboundTag":["inbound-1080","sb-inbound-443"],"domain":["geosite:google"],"outboundTag":"vless-out","ruleTag":"g"},
		{"type":"field","user":["hy-b"],"outboundTag":"landing"},
		{"type":"field","user":["vl-a","hy-a"],"outboundTag":"landing2"},
		{"type":"field","inboundTag":["sb-inbound-14758"],"user":["hy-a","stls-a"],"outboundTag":"landing3"},
		{"type":"field","inboundTag":["inbound-1080"],"user":["hy-a"],"outboundTag":"direct"},
		{"type":"field","inboundTag":["sb-inbound-9"],"outboundTag":"direct"}]}`
	var got struct {
		DomainStrategy string           `json:"domainStrategy"`
		Rules          []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(routeBridgedInbounds([]byte(router), users), &got); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"inboundTag":["api"],"outboundTag":"api","type":"field"}`,
		// an inbound stands for its own login and its clients'
		`{"inboundTag":["sbcore-bridge"],"outboundTag":"ss-out","type":"field","user":["sb-inbound-14758","sbcore:hy-a","sbcore:hy-b"]}`,
		`{"domain":["geosite:google"],"inboundTag":["inbound-1080"],"outboundTag":"vless-out","ruleTag":"g","type":"field"}`,
		`{"domain":["geosite:google"],"inboundTag":["sbcore-bridge"],"outboundTag":"vless-out","ruleTag":"g-sbcore","type":"field","user":["sb-inbound-443","sb-inbound-443-ss","sbcore:stls-a"]}`,
		// a client's email stands for its login
		`{"inboundTag":["sbcore-bridge"],"outboundTag":"landing","type":"field","user":["sbcore:hy-b"]}`,
		`{"outboundTag":"landing2","type":"field","user":["vl-a"]}`,
		`{"inboundTag":["sbcore-bridge"],"outboundTag":"landing2","type":"field","user":["sbcore:hy-a"]}`,
		// only the clients of the inbounds the rule names
		`{"inboundTag":["sbcore-bridge"],"outboundTag":"landing3","type":"field","user":["sbcore:hy-a"]}`,
		`{"inboundTag":["inbound-1080"],"outboundTag":"direct","type":"field","user":["hy-a"]}`,
		// a switched-off inbound is left as it was
		`{"inboundTag":["sb-inbound-9"],"outboundTag":"direct","type":"field"}`,
	}
	if got.DomainStrategy != "AsIs" || len(got.Rules) != len(want) {
		for _, r := range got.Rules {
			raw, _ := json.Marshal(r)
			t.Log(string(raw))
		}
		t.Fatalf("%d rules, want %d", len(got.Rules), len(want))
	}
	for i, rule := range got.Rules {
		raw, _ := json.Marshal(rule)
		if string(raw) != want[i] {
			t.Errorf("rule %d: %s\nwant     %s", i, raw, want[i])
		}
	}

	bridge, err := singboxBridgeInbound(users)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Accounts  []struct{ User string } `json:"accounts"`
		UserLevel int                     `json:"userLevel"`
	}
	json.Unmarshal(bridge.Settings, &settings)
	var logins []string
	for _, a := range settings.Accounts {
		logins = append(logins, a.User)
	}
	if raw, _ := json.Marshal(logins); string(raw) != `["sbcore","sb-inbound-14758","sb-inbound-443","sb-inbound-443-ss","sb-inbound-8443","sbcore:hy-a","sbcore:hy-b","sbcore:stls-a"]` {
		t.Errorf("bridge logins %s", raw)
	}
	if settings.UserLevel != 99 {
		t.Errorf("bridge user level %d", settings.UserLevel)
	}
}
