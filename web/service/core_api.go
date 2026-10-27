package service

import (
	"encoding/json"

	"x-ui/database/model"
	"x-ui/xray"
)

// coreAPI is the Xray API as InboundService sees it: calls on sing-box inbound
// tags become an sbcore reconcile, so no call site has to branch on protocol.
type coreAPI struct {
	xray xray.XrayAPI
}

func (c *coreAPI) Init(apiPort int) error {
	return c.xray.Init(apiPort)
}

func (c *coreAPI) Close() {
	c.xray.Close()
}

func (c *coreAPI) AddInbound(inbound []byte) error {
	var head struct {
		Tag string `json:"tag"`
	}
	if json.Unmarshal(inbound, &head) == nil && model.IsSingboxTag(head.Tag) {
		RequestSingboxApply()
		return nil
	}
	return c.xray.AddInbound(inbound)
}

func (c *coreAPI) DelInbound(tag string) error {
	if model.IsSingboxTag(tag) {
		RequestSingboxApply()
		return nil
	}
	return c.xray.DelInbound(tag)
}

func (c *coreAPI) AddUser(protocol string, inboundTag string, user map[string]any) error {
	if model.IsSingboxTag(inboundTag) {
		RequestSingboxApply()
		return nil
	}
	return c.xray.AddUser(protocol, inboundTag, user)
}

func (c *coreAPI) RemoveUser(inboundTag, email string) error {
	if model.IsSingboxTag(inboundTag) {
		RequestSingboxApply()
		return nil
	}
	// read first: Xray drops a user's online map along with the user
	ips, _ := c.xray.GetUserOnlineIPs(email)
	err := c.xray.RemoveUser(inboundTag, email)
	if err == nil && len(ips) > 0 && p != nil {
		kickXrayUser(p.GetAPIPort(), inboundTag, email, ips)
	}
	return err
}
