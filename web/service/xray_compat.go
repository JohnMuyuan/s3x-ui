package service

import (
	"encoding/json"

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
