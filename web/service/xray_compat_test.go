package service

import (
	"encoding/json"
	"reflect"
	"testing"

	"x-ui/database/model"
)

func TestDropAllowInsecure(t *testing.T) {
	in := `[{"tag":"a","protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{"serverName":"x","allowInsecure":true}}},
		{"tag":"b","protocol":"trojan","streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":false,"pinnedPeerCertSha256":"ab"}}},
		{"tag":"direct","protocol":"freedom"}]`
	var got, want any
	json.Unmarshal(dropAllowInsecure([]byte(in)), &got)
	json.Unmarshal([]byte(`[{"tag":"a","protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{"serverName":"x"}}},
		{"tag":"b","protocol":"trojan","streamSettings":{"security":"tls","tlsSettings":{"pinnedPeerCertSha256":"ab"}}},
		{"tag":"direct","protocol":"freedom"}]`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}

	clean := `[{"tag":"direct","protocol":"freedom"}]`
	if string(dropAllowInsecure([]byte(clean))) != clean {
		t.Fatal("an outbound list without allowInsecure must pass through untouched")
	}
}

func TestKcpLegacyToFinalmask(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"seed and header", `{"network":"kcp","kcpSettings":{"seed":"s3cret","header":{"type":"wechat-video"}}}`,
			`{"network":"kcp","kcpSettings":{"seed":"s3cret","header":{"type":"wechat-video"}},"finalmask":{"udp":[
				{"type":"mkcp-legacy","settings":{"header":"","value":"s3cret"}},
				{"type":"mkcp-legacy","settings":{"header":"wechat","value":""}}]}}`},
		{"keeps other masks", `{"network":"kcp","kcpSettings":{"seed":"s","header":{"type":"none"}},"finalmask":{"udp":[{"type":"salamander"}]}}`,
			`{"network":"kcp","kcpSettings":{"seed":"s","header":{"type":"none"}},"finalmask":{"udp":[{"type":"salamander"},
				{"type":"mkcp-legacy","settings":{"header":"","value":"s"}}]}}`},
		{"hand-set mask wins", `{"network":"kcp","kcpSettings":{"seed":"s"},"finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"value":"x"}}]}}`,
			`{"network":"kcp","kcpSettings":{"seed":"s"},"finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"value":"x"}}]}}`},
		{"plain kcp", `{"network":"kcp","kcpSettings":{"header":{"type":"none"}}}`, `{"network":"kcp","kcpSettings":{"header":{"type":"none"}}}`},
		{"not kcp", `{"network":"tcp","kcpSettings":{"seed":"s"}}`, `{"network":"tcp","kcpSettings":{"seed":"s"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stream, want map[string]any
			json.Unmarshal([]byte(tt.in), &stream)
			json.Unmarshal([]byte(tt.want), &want)
			kcpLegacyToFinalmask(stream)
			if !reflect.DeepEqual(stream, want) {
				t.Fatalf("got %v\nwant %v", stream, want)
			}
		})
	}
}

func TestXrayInboundConfig(t *testing.T) {
	stored := &model.Inbound{
		Protocol: model.VLESS,
		Settings: `{"decryption":"mlkem768x25519plus.native.600s.k","encryption":"mlkem768x25519plus.native.0rtt.p","fallbacks":[],
			"clients":[{"id":"a","email":"on","flow":"xtls-rprx-vision","limitIp":2,"enable":true},{"id":"b","email":"off","enable":false}]}`,
		StreamSettings: `{"network":"kcp","kcpSettings":{"seed":"s"},"externalProxy":[{"dest":"x"}]}`,
	}
	before := *stored
	cfg, err := XrayInboundConfig(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*stored, before) {
		t.Fatal("the stored inbound was modified")
	}
	var settings, stream map[string]any
	json.Unmarshal(cfg.Settings, &settings)
	json.Unmarshal(cfg.StreamSettings, &stream)
	wantClients := []any{map[string]any{"id": "a", "email": "on", "flow": "xtls-rprx-vision"}}
	if !reflect.DeepEqual(settings["clients"], wantClients) {
		t.Errorf("clients = %v, want only the enabled one with Xray's fields", settings["clients"])
	}
	for _, k := range []string{"fallbacks", "encryption"} {
		if _, ok := settings[k]; ok {
			t.Errorf("%s reached Xray next to VLESS encryption", k)
		}
	}
	if _, ok := stream["externalProxy"]; ok {
		t.Error("externalProxy reached Xray")
	}
	if fm, _ := stream["finalmask"].(map[string]any); fm == nil {
		t.Error("the mKCP seed was not carried over to finalmask")
	}

	masque := &model.Inbound{Protocol: model.MASQUE, Settings: `{"clients":[{"email":"m","password":"pw","enable":true}]}`}
	cfg, _ = XrayInboundConfig(masque)
	json.Unmarshal(cfg.Settings, &settings)
	if want := []any{map[string]any{"email": "m", "pass": "pw"}}; !reflect.DeepEqual(settings["clients"], want) {
		t.Errorf("MASQUE clients = %v, want %v", settings["clients"], want)
	}
}

func TestUnrunnableXDrive(t *testing.T) {
	xdrive := `{"network":"xdrive","xdriveSettings":{"service":"local"}}`
	tests := []struct {
		name     string
		inbound  model.Inbound
		runnable bool
	}{
		{"vless with encryption", model.Inbound{Protocol: model.VLESS, Settings: `{"decryption":"mlkem768x25519plus.native.600s.k"}`, StreamSettings: xdrive}, true},
		{"vless without encryption", model.Inbound{Protocol: model.VLESS, Settings: `{"decryption":"none"}`, StreamSettings: xdrive}, false},
		{"vmess", model.Inbound{Protocol: model.VMESS, Settings: `{}`, StreamSettings: xdrive}, false},
		{"not xdrive", model.Inbound{Protocol: model.VLESS, Settings: `{"decryption":"none"}`, StreamSettings: `{"network":"tcp"}`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := XrayInboundConfig(&tt.inbound)
			if (err == nil) != tt.runnable {
				t.Fatalf("err = %v, want runnable %v", err, tt.runnable)
			}
		})
	}
}

func TestWithUserOnline(t *testing.T) {
	var got map[string]any
	json.Unmarshal(withUserOnline([]byte(`{"levels":{"0":{"statsUserUplink":true},"1":{}},"system":{"statsInboundUplink":true}}`)), &got)
	levels := got["levels"].(map[string]any)
	for _, l := range []string{"0", "1"} {
		if levels[l].(map[string]any)["statsUserOnline"] != true {
			t.Errorf("level %s lacks statsUserOnline: %v", l, got)
		}
	}
	if levels["0"].(map[string]any)["statsUserUplink"] != true || got["system"] == nil {
		t.Errorf("other policy settings were lost: %v", got)
	}
	json.Unmarshal(withUserOnline([]byte(`{}`)), &got)
	if got["levels"].(map[string]any)["0"].(map[string]any)["statsUserOnline"] != true {
		t.Errorf("an empty policy gets no level 0: %v", got)
	}
}
