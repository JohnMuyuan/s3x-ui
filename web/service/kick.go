package service

import (
	"encoding/json"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/json_util"
	"x-ui/xray"
)

// kickXrayUser closes the connections a removed user still holds. Xray only
// stops new handshakes of a removed user, so an open connection, or a mux
// session opening new streams, would carry on. ips are the user's source
// addresses from Xray's online map, read before the removal dropped it. Only
// TCP sockets on the inbound's port are destroyed, and an address another
// online user also connects from is left alone: there is no telling whose its
// sockets are.
func kickXrayUser(apiPort int, inboundTag, email string, ips []string) {
	go func() {
		// the inbound may have been added after Xray started, so not in its config
		var port int
		if database.GetDB().Model(model.Inbound{}).Where("tag = ?", inboundTag).Select("port").Scan(&port).Error != nil || port == 0 {
			return
		}
		var api xray.XrayAPI
		if api.Init(apiPort) != nil {
			return
		}
		shared := map[string]bool{}
		users, err := api.GetOnlineUsers()
		for _, user := range users {
			if user == email {
				continue
			}
			others, _ := api.GetUserOnlineIPs(user)
			for _, ip := range others {
				shared[ip] = true
			}
		}
		api.Close()
		if err != nil {
			return
		}
		killed := 0
		for _, ip := range ips {
			if shared[ip] {
				logger.Infof("not closing connections of removed client %s from %s: another client uses that address too", email, ip)
				continue
			}
			addr, err := netip.ParseAddr(ip)
			if err != nil || addr.IsLoopback() {
				continue
			}
			out, err := exec.Command("ss", "-K", "-H", "-t", "dst", addr.Unmap().String(), "sport", "=", ":"+strconv.Itoa(port)).Output()
			if err != nil {
				logger.Warning("closing connections of", email+":", err)
				return
			}
			// ss prints each socket it destroyed
			if lines := strings.TrimSpace(string(out)); lines != "" {
				killed += len(strings.Split(lines, "\n"))
			}
		}
		if killed > 0 {
			logger.Infof("closed %d connection(s) of removed client %s", killed, email)
		}
	}()
}

// withUserOnline turns on Xray's per-user online map, which kickXrayUser
// reads, in every policy level.
func withUserOnline(policy json_util.RawMessage) json_util.RawMessage {
	var cfg map[string]any
	if err := json.Unmarshal(policy, &cfg); err != nil || cfg == nil {
		return policy
	}
	levels, _ := cfg["levels"].(map[string]any)
	if levels == nil {
		levels = map[string]any{}
		cfg["levels"] = levels
	}
	if levels["0"] == nil {
		levels["0"] = map[string]any{}
	}
	for _, raw := range levels {
		if level, ok := raw.(map[string]any); ok {
			level["statsUserOnline"] = true
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return policy
	}
	return out
}
