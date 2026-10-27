package singbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"x-ui/database/model"
	"x-ui/xray"
)

const certTLS = `{"security":"tls","tlsSettings":{"serverName":"a.example.com","minVersion":"1.2","maxVersion":"1.3","alpn":["h3","h2","http/1.1"],"certificates":[{"certificateFile":"/c.crt","keyFile":"/c.key"}]}}`

func inbound(p model.Protocol, settings, stream string, stats ...xray.ClientTraffic) *model.Inbound {
	return &model.Inbound{
		Protocol: p, Tag: model.InboundTag("", 443, p), Port: 443,
		Settings: settings, StreamSettings: stream, ClientStats: stats,
	}
}

func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err = json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBuildUsersSkipsDisabledClients(t *testing.T) {
	settings := `{"clients":[
		{"email":"on","password":"p1","enable":true},
		{"email":"off-flag","password":"p2","enable":false},
		{"email":"off-traffic","password":"p3","enable":true},
		{"email":"","password":"p4","enable":true}]}`
	ib := inbound(model.AnyTLS, settings, certTLS, xray.ClientTraffic{Email: "off-traffic", Enable: false}, xray.ClientTraffic{Email: "on", Enable: true})
	got, err := BuildInbounds(ib)
	if err != nil {
		t.Fatal(err)
	}
	users := roundTrip(t, got[0])["users"]
	want := []any{map[string]any{"name": "on", "password": "p1"}}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("users = %v, want %v", users, want)
	}
}

func TestBuildUsersFieldsPerProtocol(t *testing.T) {
	client := `{"clients":[{"email":"u@x","id":"8c3f7a52-3b0e-4b5e-9a3f-1e2d3c4b5a69","password":"pw","enable":true}]}`
	tests := []struct {
		p    model.Protocol
		want map[string]any
	}{
		{model.AnyTLS, map[string]any{"name": "u@x", "password": "pw"}},
		{model.Hysteria2, map[string]any{"name": "u@x", "password": "pw"}},
		{model.Hysteria, map[string]any{"name": "u@x", "auth_str": "pw"}},
		{model.TUIC, map[string]any{"name": "u@x", "uuid": "8c3f7a52-3b0e-4b5e-9a3f-1e2d3c4b5a69", "password": "pw"}},
		{model.Naive, map[string]any{"username": "u@x", "password": "pw"}},
		{model.Snell, map[string]any{"name": "u@x", "userkey": "pw"}},
	}
	for _, tt := range tests {
		t.Run(string(tt.p), func(t *testing.T) {
			got, err := BuildInbounds(inbound(tt.p, client, certTLS))
			if err != nil {
				t.Fatal(err)
			}
			users := roundTrip(t, got[0])["users"].([]any)
			if len(users) != 1 || !reflect.DeepEqual(users[0], tt.want) {
				t.Fatalf("users = %v, want [%v]", users, tt.want)
			}
		})
	}
}

func TestSnellSingleKey(t *testing.T) {
	settings := `{"psk":"stale","version":5,"clients":[
		{"email":"off","password":"k0","enable":false},
		{"email":"a","password":"k1","enable":true},
		{"email":"b","password":"k2","enable":true}]}`
	got, err := BuildInbounds(inbound(model.Snell, settings, ""))
	if err != nil {
		t.Fatal(err)
	}
	m := roundTrip(t, got[0])
	want := []any{map[string]any{"name": "a", "userkey": "k1"}}
	if m["psk"] != "k1" || !reflect.DeepEqual(m["users"], want) {
		t.Fatalf("psk = %v users = %v, want psk k1 and only client a", m["psk"], m["users"])
	}

	_, err = BuildInbounds(inbound(model.Snell, `{"version":5,"clients":[{"email":"a","password":"k1","enable":false}]}`, ""))
	if err == nil || !strings.Contains(err.Error(), "no enabled client") {
		t.Fatalf("err = %v, want no enabled client", err)
	}
}

func TestBuildInboundPassesOnlyWhitelistedOptions(t *testing.T) {
	settings := `{"clients":[],"congestion_control":"bbr","zero_rtt_handshake":true,"uiOnly":"x","heartbeat":""}`
	got, err := BuildInbounds(inbound(model.TUIC, settings, certTLS))
	if err != nil {
		t.Fatal(err)
	}
	m := roundTrip(t, got[0])
	if m["congestion_control"] != "bbr" || m["zero_rtt_handshake"] != true {
		t.Fatalf("whitelisted options lost: %v", m)
	}
	for _, k := range []string{"uiOnly", "heartbeat", "clients"} {
		if _, ok := m[k]; ok {
			t.Errorf("key %q leaked into sing-box inbound: %v", k, m)
		}
	}
	if m["type"] != "tuic" || m["tag"] != "sb-inbound-443" || m["listen"] != "::" || m["listen_port"] != float64(443) {
		t.Fatalf("header fields wrong: %v", m)
	}
}

func TestBuildTLS(t *testing.T) {
	inline := `{"security":"tls","tlsSettings":{"alpn":["h2"],"certificates":[{"certificate":["-----BEGIN CERTIFICATE-----","AAA"],"key":["-----BEGIN KEY-----","BBB"]}]}}`
	reality := `{"security":"reality","realitySettings":{"dest":"www.example.com:443","serverNames":["www.example.com","b.example.com"],"privateKey":"priv","shortIds":["ab12",""],"maxTimediff":60000}}`
	tests := []struct {
		name   string
		p      model.Protocol
		stream string
		want   map[string]any
		errSub string
	}{
		{"file cert keeps tcp alpn", model.AnyTLS, certTLS, map[string]any{
			"enabled": true, "server_name": "a.example.com", "min_version": "1.2", "max_version": "1.3",
			"alpn": []any{"h3", "h2", "http/1.1"}, "certificate_path": "/c.crt", "key_path": "/c.key",
		}, ""},
		{"quic drops http alpn", model.Hysteria2, certTLS, map[string]any{
			"enabled": true, "server_name": "a.example.com", "min_version": "1.2", "max_version": "1.3",
			"alpn": []any{"h3"}, "certificate_path": "/c.crt", "key_path": "/c.key",
		}, ""},
		{"quic with only http alpn leaves default", model.TUIC, inline, map[string]any{
			"enabled": true, "certificate": []any{"-----BEGIN CERTIFICATE-----", "AAA"}, "key": []any{"-----BEGIN KEY-----", "BBB"},
		}, ""},
		{"reality", model.AnyTLS, reality, map[string]any{
			"enabled": true, "server_name": "www.example.com",
			"reality": map[string]any{
				"enabled": true, "handshake": map[string]any{"server": "www.example.com", "server_port": float64(443)},
				"private_key": "priv", "short_id": []any{"ab12", ""}, "max_time_difference": "60000ms",
			},
		}, ""},
		{"quic rejects reality", model.Hysteria2, reality, nil, "cannot use REALITY"},
		{"tls required", model.Naive, `{"security":"none"}`, nil, "requires TLS"},
		{"missing certificate", model.AnyTLS, `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"","keyFile":""}]}}`, nil, "certificate is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildInbounds(inbound(tt.p, `{"clients":[]}`, tt.stream))
			if tt.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errSub) {
					t.Fatalf("err = %v, want containing %q", err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tls := roundTrip(t, got[0])["tls"]; !reflect.DeepEqual(tls, tt.want) {
				t.Fatalf("tls = %v\nwant  %v", tls, tt.want)
			}
		})
	}
}

func TestHysteria2DropsBlankObfs(t *testing.T) {
	for _, tc := range []struct {
		obfs string
		keep bool
	}{
		{`{"type":"salamander","password":""}`, false},
		{`{"type":"salamander","password":"s3cret"}`, true},
	} {
		got, err := BuildInbounds(inbound(model.Hysteria2, `{"clients":[],"obfs":`+tc.obfs+`}`, certTLS))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got[0]["obfs"]; ok != tc.keep {
			t.Errorf("obfs %s kept=%v, want %v", tc.obfs, ok, tc.keep)
		}
	}
}

func TestShadowTLSChainsInnerShadowsocks(t *testing.T) {
	settings := `{"clients":[{"email":"u","password":"tlspw","enable":true}],"handshake":{"server":"www.example.com","server_port":443},"shadowsocks":{"method":"2022-blake3-aes-128-gcm","password":"c3NwYXNzd29yZDEyMzQ1Ng=="}}`
	got, err := BuildInbounds(inbound(model.ShadowTLS, settings, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want front+inner inbounds, got %d", len(got))
	}
	front, inner := got[0], got[1]
	if front["detour"] != inner["tag"] || inner["listen"] != "127.0.0.1" || front["version"] != 3 {
		t.Fatalf("chain wrong: front=%v inner=%v", front, inner)
	}
	if _, ok := front["tls"]; ok {
		t.Fatal("ShadowTLS front must not carry its own TLS block")
	}
	if _, err = BuildInbounds(inbound(model.ShadowTLS, `{"clients":[]}`, "")); err == nil {
		t.Fatal("ShadowTLS without inner Shadowsocks must be rejected")
	}
}

func TestBuildInboundsRejectsXrayProtocol(t *testing.T) {
	if _, err := BuildInbounds(inbound(model.VLESS, `{}`, "")); err == nil {
		t.Fatal("expected error for an Xray protocol")
	}
}

func TestBuildConfigEgress(t *testing.T) {
	for egress, final := range map[string]string{EgressXray: bridgeOutboundTag, EgressDirect: "direct"} {
		cfg := roundTrip(t, BuildConfig(nil, egress, "warn"))
		if got := cfg["route"].(map[string]any)["final"]; got != final {
			t.Errorf("egress %s: final = %v, want %s", egress, got, final)
		}
		if ib := cfg["inbounds"].([]any); len(ib) != 0 {
			t.Errorf("egress %s: inbounds = %v, want empty list", egress, ib)
		}
	}
}
