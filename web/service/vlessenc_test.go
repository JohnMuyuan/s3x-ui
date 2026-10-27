package service

import (
	"reflect"
	"testing"
)

func TestParseVlessEnc(t *testing.T) {
	out := `Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.

Authentication: X25519, not Post-Quantum
"decryption": "mlkem768x25519plus.native.600s.dX",
"encryption": "mlkem768x25519plus.native.0rtt.eX"

Authentication: ML-KEM-768, Post-Quantum
"decryption": "mlkem768x25519plus.native.600s.dM"
"encryption": "mlkem768x25519plus.native.0rtt.eM"

Authentication: Truncated
"decryption": "only.half"
`
	want := []VlessEncAuth{
		{ID: "x25519", Label: "X25519, not Post-Quantum", Decryption: "mlkem768x25519plus.native.600s.dX", Encryption: "mlkem768x25519plus.native.0rtt.eX"},
		{ID: "mlkem768", Label: "ML-KEM-768, Post-Quantum", Decryption: "mlkem768x25519plus.native.600s.dM", Encryption: "mlkem768x25519plus.native.0rtt.eM"},
	}
	if got := parseVlessEnc(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}
