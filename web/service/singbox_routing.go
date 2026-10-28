package service

import (
	"encoding/json"
	"slices"

	"x-ui/database/model"
	"x-ui/singbox"
	"x-ui/util/json_util"
	"x-ui/xray"
)

// bridgeUsers are the logins on Xray's bridge inbound for the enabled inbounds
// whose traffic comes through it, by inbound tag. sbcore logs in as the
// inbound a connection came from (ShadowTLS's from its inner Shadowsocks
// inbound) and mtg as its own inbound; Xray sees the login as the user.
func bridgeUsers(inbounds []*model.Inbound) map[string][]string {
	users := map[string][]string{}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		switch {
		case ib.Protocol == model.ShadowTLS:
			users[ib.Tag] = []string{ib.Tag, ib.Tag + "-ss"}
		case ib.Protocol.IsSingbox() || ib.Protocol == model.MTProto:
			users[ib.Tag] = []string{ib.Tag}
		}
	}
	return users
}

func singboxBridgeInbound(users map[string][]string) (*xray.InboundConfig, error) {
	var logins []string
	for _, names := range users {
		logins = append(logins, names...)
	}
	slices.Sort(logins)
	b := singbox.BridgeInbound(logins)
	settings, err := json.Marshal(b["settings"])
	if err != nil {
		return nil, err
	}
	sniffing, err := json.Marshal(b["sniffing"])
	if err != nil {
		return nil, err
	}
	return &xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     singbox.BridgePort,
		Protocol: "socks",
		Settings: json_util.RawMessage(settings),
		Tag:      b["tag"].(string),
		Sniffing: json_util.RawMessage(sniffing),
	}, nil
}

// routeBridgedInbounds makes routing rules that name a sing-box or MTProto
// inbound work: that traffic reaches Xray through the bridge inbound, so such
// a rule matches the bridge and the inbound's login instead. A rule naming
// Xray inbounds too is split in two, in place. A rule that also names users
// is left alone: those are Xray clients, which bridged traffic never is.
func routeBridgedInbounds(router json_util.RawMessage, users map[string][]string) json_util.RawMessage {
	var cfg map[string]any
	if len(users) == 0 || len(router) == 0 || json.Unmarshal(router, &cfg) != nil {
		return router
	}
	rules, _ := cfg["rules"].([]any)
	out := make([]any, 0, len(rules))
	changed := false
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		tags, _ := rule["inboundTag"].([]any)
		if _, hasUser := rule["user"]; !ok || hasUser || len(tags) == 0 {
			out = append(out, r)
			continue
		}
		var keep, logins []any
		for _, t := range tags {
			tag, _ := t.(string)
			if names, ok := users[tag]; ok {
				for _, name := range names {
					logins = append(logins, name)
				}
			} else {
				keep = append(keep, t)
			}
		}
		if len(logins) == 0 {
			out = append(out, r)
			continue
		}
		changed = true
		if len(keep) > 0 {
			xrayRule := cloneMap(rule)
			xrayRule["inboundTag"] = keep
			out = append(out, xrayRule)
			if ruleTag, _ := rule["ruleTag"].(string); ruleTag != "" {
				rule = cloneMap(rule)
				rule["ruleTag"] = ruleTag + "-sbcore"
			}
		}
		bridged := cloneMap(rule)
		bridged["inboundTag"] = []any{singbox.BridgeTag}
		bridged["user"] = logins
		out = append(out, bridged)
	}
	if !changed {
		return router
	}
	cfg["rules"] = out
	raw, err := json.Marshal(cfg)
	if err != nil {
		return router
	}
	return raw
}

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
