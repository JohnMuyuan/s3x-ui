package service

import (
	"encoding/json"
	"testing"

	"x-ui/database/model"
)

func TestRouteBridgedInbounds(t *testing.T) {
	users := bridgeUsers([]*model.Inbound{
		{Tag: "sb-inbound-14758", Protocol: model.Hysteria2, Enable: true},
		{Tag: "sb-inbound-443", Protocol: model.ShadowTLS, Enable: true},
		{Tag: "sb-inbound-8443", Protocol: model.MTProto, Enable: true},
		{Tag: "sb-inbound-9", Protocol: model.TUIC, Enable: false},
		{Tag: "inbound-1080", Protocol: model.VLESS, Enable: true},
	})
	router := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api"],"outboundTag":"api"},
		{"type":"field","inboundTag":["sb-inbound-14758"],"outboundTag":"ss-out"},
		{"type":"field","inboundTag":["inbound-1080","sb-inbound-443"],"domain":["geosite:google"],"outboundTag":"vless-out","ruleTag":"g"},
		{"type":"field","inboundTag":["sb-inbound-8443"],"user":["a@x"],"outboundTag":"direct"},
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
		`{"inboundTag":["sbcore-bridge"],"outboundTag":"ss-out","type":"field","user":["sb-inbound-14758"]}`,
		`{"domain":["geosite:google"],"inboundTag":["inbound-1080"],"outboundTag":"vless-out","ruleTag":"g","type":"field"}`,
		`{"domain":["geosite:google"],"inboundTag":["sbcore-bridge"],"outboundTag":"vless-out","ruleTag":"g-sbcore","type":"field","user":["sb-inbound-443","sb-inbound-443-ss"]}`,
		// rules naming users, or a switched-off inbound, stay as they were
		`{"inboundTag":["sb-inbound-8443"],"outboundTag":"direct","type":"field","user":["a@x"]}`,
		`{"inboundTag":["sb-inbound-9"],"outboundTag":"direct","type":"field"}`,
	}
	if got.DomainStrategy != "AsIs" || len(got.Rules) != len(want) {
		t.Fatalf("got %+v", got)
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
		Accounts []struct{ User string } `json:"accounts"`
	}
	json.Unmarshal(bridge.Settings, &settings)
	var logins []string
	for _, a := range settings.Accounts {
		logins = append(logins, a.User)
	}
	if raw, _ := json.Marshal(logins); string(raw) != `["sbcore","sb-inbound-14758","sb-inbound-443","sb-inbound-443-ss","sb-inbound-8443"]` {
		t.Errorf("bridge logins %s", raw)
	}
}
