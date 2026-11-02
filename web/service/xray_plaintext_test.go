package service

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRedirectPlaintextOutbounds(t *testing.T) {
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
	out, tags := redirectPlaintextOutbounds([]byte(in))
	if want := []any{"plain-vnext", "plain-flat", "trojan-plain"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("redirected %v, want %v", tags, want)
	}
	var got []map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 15 {
		t.Fatalf("got %d outbounds, want the 12 and 3 to dial with", len(got))
	}
	for i, want := range map[int]string{12: "sg.example.com:80", 13: "1.2.3.4:80", 14: "tj.example.com:80"} {
		if redirect := got[i]["settings"].(map[string]any)["redirect"]; got[i]["protocol"] != "freedom" || redirect != want {
			t.Errorf("outbound %d: %v", i, got[i])
		}
	}
	for _, i := range []int{1, 2, 9} {
		if server := outboundServer(got[i]); server["address"] != "127.0.0.1" {
			t.Errorf("%v kept its public address", got[i]["tag"])
		}
		if plaintextToPublic(got[i]) {
			t.Errorf("%v is still refused", got[i]["tag"])
		}
		if err := xrayAccepts(got[i]); err != nil {
			t.Errorf("%v: %v", got[i]["tag"], err)
		}
	}

	// nothing to redirect: the outbounds come back untouched
	same := `[{"tag":"direct","protocol":"freedom"}]`
	if got, tags := redirectPlaintextOutbounds([]byte(same)); string(got) != same || tags != nil {
		t.Errorf("rewrote %s", got)
	}
}

func TestRedirectPlaintextKeepsTheConnection(t *testing.T) {
	var ob map[string]any
	json.Unmarshal([]byte(`{"tag":"a","protocol":"vless","sendThrough":"10.0.0.1",
		"settings":{"vnext":[{"address":"sg.example.com","port":8080,"users":[{"id":"x"}]}]},
		"streamSettings":{"network":"ws","sockopt":{"dialerProxy":"warp","mark":5}}}`), &ob)
	dial := redirectPlaintext(ob, "dial")
	var want map[string]any
	json.Unmarshal([]byte(`{"tag":"dial","protocol":"freedom","sendThrough":"10.0.0.1","settings":{"redirect":"sg.example.com:8080"},
		"streamSettings":{"sockopt":{"dialerProxy":"warp","mark":5}}}`), &want)
	if !reflect.DeepEqual(dial, want) {
		t.Errorf("dial %v\nwant %v", dial, want)
	}
	stream := ob["streamSettings"].(map[string]any)
	if host := stream["wsSettings"].(map[string]any)["host"]; host != "sg.example.com:8080" {
		t.Errorf("host %v", host)
	}
	if !reflect.DeepEqual(stream["sockopt"], map[string]any{"dialerProxy": "dial"}) || ob["sendThrough"] != nil {
		t.Errorf("outbound %v", ob)
	}

	for name, section := range map[string]map[string]any{
		"own host":    {"host": "cdn.example.com"},
		"host header": {"headers": map[string]any{"Host": "cdn.example.com"}},
	} {
		stream := map[string]any{"network": "ws", "wsSettings": section}
		keepTransportHost(stream, "sg.example.com", "80")
		if host, _ := section["host"].(string); host != "" && host != "cdn.example.com" {
			t.Errorf("%s: host %v", name, host)
		}
	}
	stream = map[string]any{"network": "grpc"}
	keepTransportHost(stream, "sg.example.com", "80")
	if authority := stream["grpcSettings"].(map[string]any)["authority"]; authority != "sg.example.com" {
		t.Errorf("authority %v", authority)
	}
}
