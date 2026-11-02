package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"e2e.invalid"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

func TestPinInsecureOutbounds(t *testing.T) {
	first, firstPin := selfSigned(t)
	second, secondPin := selfSigned(t)
	var current atomic.Pointer[tls.Certificate]
	current.Store(&first)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	certPins = map[certTarget]string{}
	port := listener.Addr().(*net.TCPAddr).Port

	outbound := func(tlsSettings string) string {
		return `{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":` + strconv.Itoa(port) + `}]},
			"streamSettings":{"security":"tls","tlsSettings":` + tlsSettings + `}}`
	}
	in := `[` + outbound(`{"serverName":"e2e.invalid","allowInsecure":true,"pinnedPeerCertSha256":""}`) + `,` +
		outbound(`{"serverName":"e2e.invalid","allowInsecure":true,"pinnedPeerCertSha256":"ab"}`) + `,` +
		outbound(`{"serverName":"e2e.invalid"}`) + `]`
	tlsOf := func(raw []byte) []map[string]any {
		var list []map[string]any
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		var settings []map[string]any
		for _, ob := range list {
			settings = append(settings, ob["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any))
		}
		return settings
	}

	got := tlsOf(pinInsecureOutbounds([]byte(in)))
	if got[0]["pinnedPeerCertSha256"] != firstPin || got[0]["allowInsecure"] != nil {
		t.Errorf("first outbound %v, want pin %s", got[0], firstPin)
	}
	if got[1]["pinnedPeerCertSha256"] != "ab" {
		t.Errorf("a pin set by hand changed: %v", got[1])
	}
	if got[2]["pinnedPeerCertSha256"] != nil {
		t.Errorf("an outbound that verifies was pinned: %v", got[2])
	}

	if RefreshOutboundCertPins() {
		t.Error("refresh reported a change with the same certificate")
	}
	current.Store(&second)
	if !RefreshOutboundCertPins() {
		t.Error("refresh missed the new certificate")
	}
	if got := tlsOf(pinInsecureOutbounds([]byte(in))); got[0]["pinnedPeerCertSha256"] != secondPin {
		t.Errorf("after the refresh %v, want pin %s", got[0], secondPin)
	}

	// the server goes away: its pin stays
	listener.Close()
	if RefreshOutboundCertPins() {
		t.Error("an unreachable server reported a change")
	}
	if got := tlsOf(pinInsecureOutbounds([]byte(in))); got[0]["pinnedPeerCertSha256"] != secondPin {
		t.Errorf("the pin went with the server: %v", got[0])
	}

	// a server never reached leaves allowInsecure to dropAllowInsecure
	certPins = map[certTarget]string{}
	if got := tlsOf(pinInsecureOutbounds([]byte(in))); got[0]["allowInsecure"] != true {
		t.Errorf("unreachable outbound changed: %v", got[0])
	}
	certPins = map[certTarget]string{}
}
