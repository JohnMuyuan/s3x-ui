package service

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"x-ui/logger"
	"x-ui/util/common"

	"golang.org/x/crypto/curve25519"
)

// WARP exit address rotation. Cloudflare gives each registered device its
// own exit address, so rotating registers a new device with a new key pair,
// takes the WARP+ license over to it, and restarts Xray with it. (Swapping
// the outbound through Xray's API would leave the old WireGuard device
// running: Xray does not close a removed outbound.)
const warpTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

var warpRotateLock sync.Mutex

type WarpRotation struct {
	OldIP     string `json:"oldIp"`
	IP        string `json:"ip"`
	Loc       string `json:"loc"`
	RotatedAt int64  `json:"rotatedAt"`
	Interval  int    `json:"interval"`
	Note      string `json:"note,omitempty"`
}

// the part of a registration Xray needs
type warpRegistration struct {
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	Account struct {
		AccountType string `json:"account_type"`
	} `json:"account"`
}

// RotationInfo is the rotation schedule, the last rotation and, when the
// WARP outbound runs, its exit address now.
func (s *WarpService) RotationInfo() *WarpRotation {
	info := &WarpRotation{}
	info.Interval, _ = s.GetWarpRotateInterval()
	info.RotatedAt, _ = s.GetWarpRotatedAt()
	info.IP, info.Loc, _ = OutboundExit("warp")
	return info
}

// RotateDue rotates when the interval has passed since the last rotation.
func (s *WarpService) RotateDue() {
	hours, _ := s.GetWarpRotateInterval()
	if hours <= 0 {
		return
	}
	last, _ := s.GetWarpRotatedAt()
	if time.Since(time.UnixMilli(last)) < time.Duration(hours)*time.Hour {
		return
	}
	if res, err := s.Rotate(); err != nil {
		logger.Warning("WARP rotation:", err)
	} else {
		logger.Infof("WARP rotated: %s -> %s %s %s", res.OldIP, res.IP, res.Loc, res.Note)
	}
}

func (s *WarpService) Rotate() (*WarpRotation, error) {
	warpRotateLock.Lock()
	defer warpRotateLock.Unlock()
	// a failed attempt waits for the next interval too
	s.SetWarpRotatedAt(time.Now().UnixMilli())

	var old map[string]string
	if raw, _ := s.GetWarp(); json.Unmarshal([]byte(raw), &old) != nil || old["device_id"] == "" {
		return nil, common.NewError("register WARP first")
	}
	tmpl, err := s.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(tmpl), &cfg); err != nil {
		return nil, err
	}
	var warpOutbound map[string]any
	outbounds, _ := cfg["outbounds"].([]any)
	for _, o := range outbounds {
		if ob, ok := o.(map[string]any); ok && ob["tag"] == "warp" {
			warpOutbound = ob
		}
	}
	if warpOutbound == nil {
		return nil, common.NewError("add the WARP outbound first")
	}

	res := &WarpRotation{}
	res.OldIP, _, _ = OutboundExit("warp")
	premium := false
	if raw, err := s.GetWarpConfig(); err == nil {
		var reg warpRegistration
		json.Unmarshal([]byte(raw), &reg)
		premium = reg.Account.AccountType != "" && reg.Account.AccountType != "free"
	}

	secretKey, publicKey, err := wireguardKeyPair()
	if err != nil {
		return nil, err
	}
	raw, err := s.RegWarp(secretKey, publicKey)
	if err != nil {
		return nil, err
	}
	var reg struct {
		Config warpRegistration `json:"config"`
	}
	if err := json.Unmarshal([]byte(raw), &reg); err != nil || len(reg.Config.Config.Peers) == 0 {
		return nil, common.NewError("unexpected WARP registration")
	}
	// the old device goes first: a WARP+ license holds a few devices only
	s.deleteDevice(old["device_id"], old["access_token"])
	if premium {
		if _, err := s.SetWarpLicense(old["license_key"]); err != nil {
			res.Note = "WARP+ license not moved: " + err.Error()
		}
	}

	settings, _ := warpOutbound["settings"].(map[string]any)
	if settings == nil {
		settings = map[string]any{}
		warpOutbound["settings"] = settings
	}
	conf := reg.Config.Config
	settings["secretKey"] = secretKey
	var addresses []string
	if conf.Interface.Addresses.V4 != "" {
		addresses = append(addresses, conf.Interface.Addresses.V4+"/32")
	}
	if conf.Interface.Addresses.V6 != "" {
		addresses = append(addresses, conf.Interface.Addresses.V6+"/128")
	}
	settings["address"] = addresses
	reserved := []int{}
	clientID, _ := base64.StdEncoding.DecodeString(conf.ClientID)
	for _, b := range clientID {
		reserved = append(reserved, int(b))
	}
	settings["reserved"] = reserved
	peer := map[string]any{}
	if peers, _ := settings["peers"].([]any); len(peers) > 0 {
		if p, ok := peers[0].(map[string]any); ok {
			peer = p
		}
	}
	peer["publicKey"] = conf.Peers[0].PublicKey
	peer["endpoint"] = conf.Peers[0].Endpoint.Host
	settings["peers"] = []any{peer}

	newTmpl, err := marshalTemplate(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.saveSetting("xrayTemplateConfig", newTmpl); err != nil {
		return nil, err
	}
	var xrayService XrayService
	if err := xrayService.RestartXray(false); err != nil {
		return nil, err
	}
	res.IP, res.Loc = warpExitAfterStart()
	// On a kernel TUN the first start with new keys often never completes
	// the handshake, while the next start does.
	if userspace, _ := settings["noKernelTun"].(bool); res.IP == "" && !userspace {
		if err := xrayService.RestartXray(true); err != nil {
			return nil, err
		}
		res.IP, res.Loc = warpExitAfterStart()
	}
	res.RotatedAt = time.Now().UnixMilli()
	res.Interval, _ = s.GetWarpRotateInterval()
	return res, nil
}

// warpExitAfterStart reads the WARP exit of a just started Xray, giving the
// tunnel a moment to come up.
func warpExitAfterStart() (ip, loc string) {
	for i := 0; i < 2 && ip == ""; i++ {
		time.Sleep(time.Second)
		ip, loc, _ = OutboundExit("warp")
	}
	return ip, loc
}

// warpFields are the parts of the WARP outbound a registration sets.
var warpFields = []string{"secretKey", "address", "reserved", "peers"}

// keepCurrentWarp gives the WARP outbound of a template being saved the
// current registration when it carries an earlier one: the page was loaded
// before a rotation, and saving it would put back a deleted device.
func keepCurrentWarp(newTmpl, storedTmpl, warpData string) string {
	var data map[string]string
	if json.Unmarshal([]byte(warpData), &data) != nil || data["private_key"] == "" {
		return newTmpl
	}
	warpSettings := func(cfg map[string]any) map[string]any {
		outbounds, _ := cfg["outbounds"].([]any)
		for _, o := range outbounds {
			if ob, ok := o.(map[string]any); ok && ob["tag"] == "warp" {
				settings, _ := ob["settings"].(map[string]any)
				return settings
			}
		}
		return nil
	}
	var incoming, stored map[string]any
	if json.Unmarshal([]byte(newTmpl), &incoming) != nil || json.Unmarshal([]byte(storedTmpl), &stored) != nil {
		return newTmpl
	}
	in, cur := warpSettings(incoming), warpSettings(stored)
	if in == nil || cur == nil || in["secretKey"] == data["private_key"] || cur["secretKey"] != data["private_key"] {
		return newTmpl
	}
	for _, field := range warpFields {
		in[field] = cur[field]
	}
	fixed, err := marshalTemplate(incoming)
	if err != nil {
		return newTmpl
	}
	return fixed
}

func marshalTemplate(cfg map[string]any) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func (s *WarpService) deleteDevice(id, token string) {
	req, err := http.NewRequest(http.MethodDelete, "https://api.cloudflareclient.com/v0a2158/reg/"+id, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, err := PanelHTTPClient(15 * time.Second).Do(req); err == nil {
		resp.Body.Close()
	}
}

func wireguardKeyPair() (secretKey, publicKey string, err error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// OutboundExit reads the address and location an outbound's traffic leaves
// from, as Cloudflare sees it.
func OutboundExit(tag string) (ip, loc string, err error) {
	client, err := probeClient(tag)
	if err != nil {
		return "", "", err
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get(warpTraceURL)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		key, value, _ := strings.Cut(sc.Text(), "=")
		switch key {
		case "ip":
			ip = value
		case "loc":
			loc = value
		}
	}
	return ip, loc, nil
}
