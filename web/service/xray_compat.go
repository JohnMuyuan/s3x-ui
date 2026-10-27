package service

import (
	"encoding/json"
	"fmt"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/json_util"
)

// dropAllowInsecure removes "allowInsecure" from the outbounds' TLS settings.
// Xray 26 refuses to start at all when it is true; outbounds saved by 3x-ui
// 2.6.2 still carry it, and one of them would take every inbound down. Such an
// outbound now verifies its certificate, so the warning points at the fields
// that replace it.
func dropAllowInsecure(outbounds json_util.RawMessage) json_util.RawMessage {
	if len(outbounds) == 0 {
		return outbounds
	}
	var list []map[string]any
	if err := json.Unmarshal(outbounds, &list); err != nil {
		return outbounds
	}
	changed := false
	for _, ob := range list {
		stream, _ := ob["streamSettings"].(map[string]any)
		tls, _ := stream["tlsSettings"].(map[string]any)
		insecure, ok := tls["allowInsecure"]
		if !ok {
			continue
		}
		delete(tls, "allowInsecure")
		changed = true
		if insecure == true {
			logger.Warningf("outbound %v: Xray no longer supports allowInsecure; set pinnedPeerCertSha256 or verifyPeerCertByName instead", ob["tag"])
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

// unrunnable names inbounds Xray would refuse, which would stop every other
// inbound with them: XDRIVE only runs as VLESS with encryption.
func unrunnable(inbound *model.Inbound) error {
	var stream struct {
		Network string `json:"network"`
	}
	json.Unmarshal([]byte(inbound.StreamSettings), &stream)
	if stream.Network != "xdrive" {
		return nil
	}
	if inbound.Protocol != model.VLESS {
		return fmt.Errorf("inbound %s: XDRIVE can only be used by VLESS", inbound.Tag)
	}
	var settings struct {
		Decryption string `json:"decryption"`
	}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	if settings.Decryption == "" || settings.Decryption == "none" {
		return fmt.Errorf("inbound %s: XDRIVE needs VLESS encryption", inbound.Tag)
	}
	return nil
}

// kcpHeaderMask maps 3x-ui's mKCP header types to Xray's mkcp-legacy names.
var kcpHeaderMask = map[string]string{
	"dns":          "dns",
	"dtls":         "dtls",
	"srtp":         "srtp",
	"utp":          "utp",
	"wechat-video": "wechat",
	"wireguard":    "wireguard",
}

// kcpLegacyToFinalmask carries a 2.6.2 mKCP seed and header disguise over to
// the finalmask masks Xray 26 reads instead; it ignores kcpSettings.seed and
// .header without a word, so clients that still send them could no longer
// connect. Masks already set by hand win. Seed comes first: the last mask is
// outermost, putting the header around the cipher as before.
func kcpLegacyToFinalmask(stream map[string]any) {
	if network, _ := stream["network"].(string); network != "kcp" {
		return
	}
	kcp, _ := stream["kcpSettings"].(map[string]any)
	seed, _ := kcp["seed"].(string)
	header, _ := kcp["header"].(map[string]any)
	headerType, _ := header["type"].(string)
	maskHeader := kcpHeaderMask[headerType]
	if seed == "" && maskHeader == "" {
		return
	}
	finalmask, _ := stream["finalmask"].(map[string]any)
	if finalmask == nil {
		finalmask = map[string]any{}
	}
	udp, _ := finalmask["udp"].([]any)
	for _, m := range udp {
		if mask, _ := m.(map[string]any); mask["type"] == "mkcp-legacy" {
			return
		}
	}
	if seed != "" {
		udp = append(udp, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": "", "value": seed}})
	}
	if maskHeader != "" {
		udp = append(udp, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": maskHeader, "value": ""}})
	}
	finalmask["udp"] = udp
	stream["finalmask"] = finalmask
}
