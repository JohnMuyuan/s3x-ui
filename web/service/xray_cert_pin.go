package service

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"x-ui/logger"
	"x-ui/util/json_util"
)

const (
	certPinTimeout = 5 * time.Second
	// certTrusted marks a server whose certificate verifies as it is.
	certTrusted = "trusted"
)

type certTarget struct {
	address, port, serverName string
}

var (
	certPinsLock sync.Mutex
	// The state of the servers the outbounds use: certTrusted, a certificate's
	// SHA-256, or "" until the server has answered.
	certPins = map[certTarget]string{}
)

// pinInsecureOutbounds replaces allowInsecure, which Xray 26 no longer has,
// with the server's current certificate: outbounds saved with it go on
// accepting a self-signed or mismatched one. RefreshOutboundCertPins follows
// the server when that certificate changes.
func pinInsecureOutbounds(outbounds json_util.RawMessage) json_util.RawMessage {
	if len(outbounds) == 0 {
		return outbounds
	}
	var list []map[string]any
	if err := json.Unmarshal(outbounds, &list); err != nil {
		return outbounds
	}
	settings := map[certTarget][]map[string]any{}
	for _, ob := range list {
		stream, _ := ob["streamSettings"].(map[string]any)
		tlsSettings, _ := stream["tlsSettings"].(map[string]any)
		server := outboundServer(ob)
		address, _ := server["address"].(string)
		if stream["security"] != "tls" || tlsSettings["allowInsecure"] != true || address == "" {
			continue
		}
		pinned, _ := tlsSettings["pinnedPeerCertSha256"].(string)
		names, _ := tlsSettings["verifyPeerCertByName"].(string)
		if pinned != "" || names != "" {
			continue
		}
		target := certTarget{address: strings.Trim(address, "[]"), port: fmt.Sprint(server["port"])}
		target.serverName, _ = tlsSettings["serverName"].(string)
		if target.serverName == "" {
			target.serverName = target.address
		}
		settings[target] = append(settings[target], tlsSettings)
	}
	targets := make([]certTarget, 0, len(settings))
	for target := range settings {
		targets = append(targets, target)
	}
	pins := certPinsFor(targets)
	changed := false
	for target, group := range settings {
		pin := pins[target]
		if pin == "" {
			continue
		}
		changed = true
		for _, tlsSettings := range group {
			delete(tlsSettings, "allowInsecure")
			if pin != certTrusted {
				tlsSettings["pinnedPeerCertSha256"] = pin
			}
		}
	}
	if !changed {
		return outbounds
	}
	out, err := json.Marshal(list)
	if err != nil {
		return outbounds
	}
	return out
}

// certPinsFor makes targets the servers being followed, and reads the
// certificates of those not seen before.
func certPinsFor(targets []certTarget) map[certTarget]string {
	certPinsLock.Lock()
	defer certPinsLock.Unlock()
	pins := make(map[certTarget]string, len(targets))
	var unseen []certTarget
	for _, target := range targets {
		if pin, ok := certPins[target]; ok {
			pins[target] = pin
		} else {
			pins[target] = ""
			unseen = append(unseen, target)
		}
	}
	certPins = pins
	updateCertPins(unseen)
	return pins
}

// RefreshOutboundCertPins reads the followed servers' certificates again and
// reports whether Xray needs the new ones. A server that doesn't answer keeps
// its pin.
func RefreshOutboundCertPins() bool {
	certPinsLock.Lock()
	defer certPinsLock.Unlock()
	targets := make([]certTarget, 0, len(certPins))
	for target := range certPins {
		targets = append(targets, target)
	}
	return updateCertPins(targets)
}

func updateCertPins(targets []certTarget) bool {
	read := make([]string, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Go(func() {
			read[i] = readCertPin(target)
		})
	}
	wg.Wait()
	changed := false
	for i, target := range targets {
		if read[i] != "" && read[i] != certPins[target] {
			certPins[target] = read[i]
			changed = true
		}
	}
	return changed
}

func readCertPin(target certTarget) string {
	dialer := &net.Dialer{Timeout: certPinTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target.address, target.port), &tls.Config{
		ServerName:         target.serverName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		logger.Warningf("no certificate from %s to pin: %v", net.JoinHostPort(target.address, target.port), err)
		return ""
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	// A valid certificate needs no pin, and a CDN's differs between its edges.
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: target.serverName, Intermediates: intermediates}); err == nil {
		return certTrusted
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:])
}
