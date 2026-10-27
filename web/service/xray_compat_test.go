package service

import (
	"encoding/json"
	"reflect"
	"testing"
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
