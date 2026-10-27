// Package amneziawg serves AmneziaWG inbounds: WireGuard with junk packets,
// padded handshakes and custom message types, which DPI does not recognise.
// Each inbound is an amneziawg-go device running inside the panel on its own
// TUN interface; clients are its peers, and their traffic is NATed out of the
// server directly rather than through Xray.
package amneziawg

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"x-ui/database/model"
)

// Params are AmneziaWG 1.0's obfuscation settings; server and clients must
// agree on all of them.
type Params struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
}

func (p Params) validate() error {
	switch {
	case p.Jc < 0 || p.Jc > 128:
		return fmt.Errorf("Jc must be 0-128")
	case p.Jmin < 0 || p.Jmax > 1280 || p.Jmin > p.Jmax:
		return fmt.Errorf("need 0 <= Jmin <= Jmax <= 1280")
	case p.S1 < 0 || p.S1 > 1132 || p.S2 < 0 || p.S2 > 1188:
		return fmt.Errorf("S1 must be 0-1132 and S2 0-1188")
	case p.S1+56 == p.S2:
		// the padded handshake init and response would be the same size
		return fmt.Errorf("S2 must not equal S1 + 56")
	}
	h := []uint32{p.H1, p.H2, p.H3, p.H4}
	for i, v := range h {
		if v < 5 || slices.Contains(h[i+1:], v) {
			return fmt.Errorf("H1-H4 must be distinct and above 4")
		}
	}
	return nil
}

type Peer struct {
	Email        string
	PublicKey    string // hex, as UAPI takes it
	PresharedKey string // hex, or empty
	Address      netip.Prefix
}

// Instance is what one AmneziaWG inbound needs running.
type Instance struct {
	Id         int
	Tag        string
	Port       int
	Iface      string
	PrivateKey string // hex
	Address    netip.Prefix
	MTU        int
	Params     Params
	Peers      []Peer
}

func keyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("not a WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// FromInbound derives the instance for an inbound; false when it is not an
// enabled AmneziaWG inbound with valid settings and an enabled client.
// Clients disabled by hand or by the panel (quota, expiry) are left out.
func FromInbound(ib *model.Inbound) (Instance, []string, bool) {
	if ib == nil || !ib.Enable || ib.Protocol != model.AmneziaWG {
		return Instance{}, nil, false
	}
	var s struct {
		Params
		SecretKey string `json:"secretKey"`
		Address   string `json:"address"`
		MTU       int    `json:"mtu"`
		Clients   []struct {
			Email        string `json:"email"`
			PublicKey    string `json:"publicKey"`
			PreSharedKey string `json:"preSharedKey"`
			Address      string `json:"address"`
			Enable       bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(ib.Settings), &s); err != nil {
		return Instance{}, []string{err.Error()}, false
	}
	inst := Instance{Id: ib.Id, Tag: ib.Tag, Port: ib.Port, Iface: "awg" + strconv.Itoa(ib.Id), MTU: s.MTU, Params: s.Params}
	var err error
	if inst.PrivateKey, err = keyHex(s.SecretKey); err != nil {
		return Instance{}, []string{"server private key: " + err.Error()}, false
	}
	if inst.Address, err = netip.ParsePrefix(strings.TrimSpace(s.Address)); err != nil || !inst.Address.Addr().Is4() {
		return Instance{}, []string{"server address must be an IPv4 CIDR like 10.66.66.1/24"}, false
	}
	if err := s.Params.validate(); err != nil {
		return Instance{}, []string{err.Error()}, false
	}
	if inst.MTU <= 0 {
		inst.MTU = 1420
	}
	disabled := map[string]bool{}
	for _, st := range ib.ClientStats {
		if !st.Enable {
			disabled[st.Email] = true
		}
	}
	var problems []string
	taken := map[netip.Addr]bool{inst.Address.Addr(): true}
	for _, c := range s.Clients {
		if !c.Enable || disabled[c.Email] || c.Email == "" {
			continue
		}
		peer := Peer{Email: c.Email}
		if peer.PublicKey, err = keyHex(c.PublicKey); err != nil {
			problems = append(problems, fmt.Sprintf("client %s: public key: %v", c.Email, err))
			continue
		}
		if c.PreSharedKey != "" {
			if peer.PresharedKey, err = keyHex(c.PreSharedKey); err != nil {
				problems = append(problems, fmt.Sprintf("client %s: preshared key: %v", c.Email, err))
				continue
			}
		}
		addr, err := netip.ParsePrefix(strings.TrimSpace(c.Address))
		if err != nil || addr.Bits() != 32 || !inst.Address.Contains(addr.Addr()) || taken[addr.Addr()] {
			problems = append(problems, fmt.Sprintf("client %s: address %q must be a free /32 in %s", c.Email, c.Address, inst.Address.Masked()))
			continue
		}
		taken[addr.Addr()] = true
		peer.Address = addr
		inst.Peers = append(inst.Peers, peer)
	}
	return inst, problems, len(inst.Peers) > 0
}

// structure covers everything but the peers, which change live.
func (inst Instance) structure() string {
	return fmt.Sprintf("%s|%d|%s|%s|%d|%+v", inst.Iface, inst.Port, inst.PrivateKey, inst.Address, inst.MTU, inst.Params)
}

func (inst Instance) deviceConfig() string {
	p := inst.Params
	return fmt.Sprintf("private_key=%s\nlisten_port=%d\njc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		inst.PrivateKey, inst.Port, p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.H1, p.H2, p.H3, p.H4)
}

func (p Peer) config() string {
	psk := p.PresharedKey
	if psk == "" {
		psk = strings.Repeat("0", 64)
	}
	return fmt.Sprintf("public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", p.PublicKey, psk, p.Address)
}

// peersDiff is the UAPI text taking a device from the applied peers to the
// wanted ones, keyed by public key; untouched peers keep their sessions.
func peersDiff(applied map[string]string, want []Peer) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range want {
		seen[p.PublicKey] = true
		if conf := p.config(); applied[p.PublicKey] != conf {
			b.WriteString(conf)
		}
	}
	for key := range applied {
		if !seen[key] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", key)
		}
	}
	return b.String()
}

type counters struct{ rx, tx int64 }

// parseStats reads per-peer byte counters from a UAPI get, by public key.
func parseStats(uapi string) map[string]counters {
	out := map[string]counters{}
	key := ""
	for _, line := range strings.Split(uapi, "\n") {
		k, v, _ := strings.Cut(line, "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "public_key":
			key = v
			out[key] = counters{}
		case "rx_bytes":
			c := out[key]
			c.rx = n
			out[key] = c
		case "tx_bytes":
			c := out[key]
			c.tx = n
			out[key] = c
		}
	}
	return out
}

// Traffic is the bytes one client moved since the last collection.
type Traffic struct {
	Tag, Email string
	Up, Down   int64
}
