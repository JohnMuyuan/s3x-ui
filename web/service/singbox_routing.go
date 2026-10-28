package service

import (
	"encoding/json"
	"slices"

	"x-ui/database/model"
	"x-ui/singbox"
	"x-ui/util/json_util"
	"x-ui/xray"
)

// bridgeLogins are the logins on Xray's bridge inbound, for the enabled
// inbounds whose traffic comes through it. sbcore logs in as the client a
// connection belongs to ("sbcore:" + its email), or as the inbound when the
// connection has no client (ShadowTLS's inner Shadowsocks inbound); mtg logs
// in as its inbound. Xray sees the login as the user, so routing rules can
// tell these inbounds and their clients apart.
type bridgeLogins struct {
	byTag   map[string][]string     // every login an inbound's traffic may use
	byEmail map[string]bridgeClient // a sing-box client's login
}

type bridgeClient struct {
	tag, login string
}

func bridgeUsers(inbounds []*model.Inbound) *bridgeLogins {
	b := &bridgeLogins{byTag: map[string][]string{}, byEmail: map[string]bridgeClient{}}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		switch {
		case ib.Protocol.IsSingbox():
			logins := []string{ib.Tag}
			if ib.Protocol == model.ShadowTLS {
				logins = append(logins, ib.Tag+"-ss")
			}
			clients, _ := new(InboundService).GetClients(ib)
			for _, c := range clients {
				if c.Email == "" {
					continue
				}
				login := singbox.BridgeClientPrefix + c.Email
				logins = append(logins, login)
				b.byEmail[c.Email] = bridgeClient{tag: ib.Tag, login: login}
			}
			b.byTag[ib.Tag] = logins
		case ib.Protocol == model.MTProto:
			b.byTag[ib.Tag] = []string{ib.Tag}
		}
	}
	return b
}

func (b *bridgeLogins) empty() bool {
	return len(b.byTag) == 0
}

func singboxBridgeInbound(b *bridgeLogins) (*xray.InboundConfig, error) {
	var logins []string
	for _, names := range b.byTag {
		logins = append(logins, names...)
	}
	slices.Sort(logins)
	bridge := singbox.BridgeInbound(logins)
	settings, err := json.Marshal(bridge["settings"])
	if err != nil {
		return nil, err
	}
	sniffing, err := json.Marshal(bridge["sniffing"])
	if err != nil {
		return nil, err
	}
	return &xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     singbox.BridgePort,
		Protocol: "socks",
		Settings: json_util.RawMessage(settings),
		Tag:      bridge["tag"].(string),
		Sniffing: json_util.RawMessage(sniffing),
	}, nil
}

// routeBridgedInbounds makes routing rules on sing-box and MTProto inbounds,
// and on sing-box clients, work. That traffic reaches Xray through the bridge
// inbound, so such a rule is matched on the bridge and the logins instead: an
// inbound stands for all its logins, a client's email for its own. A rule that
// also names Xray inbounds or clients is split in two, in place.
func routeBridgedInbounds(router json_util.RawMessage, b *bridgeLogins) json_util.RawMessage {
	var cfg map[string]any
	if b.empty() || len(router) == 0 || json.Unmarshal(router, &cfg) != nil {
		return router
	}
	rules, _ := cfg["rules"].([]any)
	out := make([]any, 0, len(rules))
	changed := false
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		xrayRule, logins := b.splitRule(rule)
		if len(logins) == 0 {
			out = append(out, r)
			continue
		}
		changed = true
		if xrayRule != nil {
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

// splitRule returns the bridge logins a rule covers, and what is left of it
// for Xray's own inbounds and clients (nil when nothing is).
func (b *bridgeLogins) splitRule(rule map[string]any) (map[string]any, []any) {
	tags, hasTags := rule["inboundTag"].([]any)
	users, hasUsers := rule["user"].([]any)
	var logins, keepTags, keepUsers []any
	bridgedTag := map[string]bool{}
	for _, t := range tags {
		tag, _ := t.(string)
		if _, ok := b.byTag[tag]; ok {
			bridgedTag[tag] = true
		} else {
			keepTags = append(keepTags, t)
		}
	}
	if hasUsers {
		// Clients of the named inbounds, or of any when none are named.
		for _, u := range users {
			email, _ := u.(string)
			if c, ok := b.byEmail[email]; ok {
				if !hasTags || bridgedTag[c.tag] {
					logins = append(logins, c.login)
				}
			} else {
				keepUsers = append(keepUsers, u)
			}
		}
	} else {
		for _, t := range tags {
			tag, _ := t.(string)
			if bridgedTag[tag] {
				for _, login := range b.byTag[tag] {
					logins = append(logins, login)
				}
			}
		}
	}
	if len(logins) == 0 {
		return rule, nil
	}
	// What Xray's own inbounds and clients can still match.
	if (hasTags && len(keepTags) == 0) || (hasUsers && len(keepUsers) == 0) {
		return nil, logins
	}
	xrayRule := cloneMap(rule)
	if hasTags {
		xrayRule["inboundTag"] = keepTags
	}
	if hasUsers {
		xrayRule["user"] = keepUsers
	}
	return xrayRule, logins
}

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
