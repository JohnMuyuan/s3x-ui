package model

import (
	"fmt"
	"strings"

	"x-ui/util/json_util"
	"x-ui/xray"
)

type Protocol string

const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	DOKODEMO    Protocol = "dokodemo-door"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Socks       Protocol = "socks"
	WireGuard   Protocol = "wireguard"
	MASQUE      Protocol = "masque"
	Tun         Protocol = "tun"

	// Served by the sbcore sing-box sidecar, not by Xray.
	AnyTLS    Protocol = "anytls"
	Hysteria  Protocol = "hysteria"
	Hysteria2 Protocol = "hysteria2"
	TUIC      Protocol = "tuic"
	Naive     Protocol = "naive"
	ShadowTLS Protocol = "shadowtls"
	Snell     Protocol = "snell"

	// Served by mtg-multi processes.
	MTProto Protocol = "mtproto"
)

// SingboxTagPrefix marks inbounds that live in a sidecar (sbcore or mtg), so
// Xray API calls on their tags can be routed there without a database lookup.
const SingboxTagPrefix = "sb-"

func (p Protocol) IsSingbox() bool {
	switch p {
	case AnyTLS, Hysteria, Hysteria2, TUIC, Naive, ShadowTLS, Snell:
		return true
	}
	return false
}

// KeysClientsByEmail reports protocols whose clients are addressed by email
// rather than by id or password in client edit and delete calls.
func (p Protocol) KeysClientsByEmail() bool {
	return p == Shadowsocks || p == MASQUE || p.IsSidecar()
}

// IsSidecar reports protocols Xray does not run: sbcore's and MTProto.
func (p Protocol) IsSidecar() bool {
	return p.IsSingbox() || p == MTProto
}

func IsSingboxTag(tag string) bool {
	return strings.HasPrefix(tag, SingboxTagPrefix)
}

func InboundTag(listen string, port int, protocol Protocol) string {
	tag := fmt.Sprintf("inbound-%v", port)
	if listen != "" && listen != "0.0.0.0" && listen != "::" && listen != "::0" {
		tag = fmt.Sprintf("inbound-%v:%v", listen, port)
	}
	if protocol.IsSidecar() {
		tag = SingboxTagPrefix + tag
	}
	return tag
}

type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Id          int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId      int                  `json:"-"`
	Up          int64                `json:"up" form:"up"`
	Down        int64                `json:"down" form:"down"`
	Total       int64                `json:"total" form:"total"`
	Remark      string               `json:"remark" form:"remark"`
	Enable      bool                 `json:"enable" form:"enable"`
	ExpiryTime  int64                `json:"expiryTime" form:"expiryTime"`
	ClientStats []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
	Allocate       string   `json:"allocate" form:"allocate"`
}

type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	if listen != "" {
		listen = fmt.Sprintf("\"%v\"", listen)
	}
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
		Allocate:       json_util.RawMessage(i.Allocate),
	}
}

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type Client struct {
	ID         string `json:"id"`
	Security   string `json:"security"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB" form:"totalGB"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`
	Enable     bool   `json:"enable" form:"enable"`
	TgID       int64  `json:"tgId" form:"tgId"`
	SubID      string `json:"subId" form:"subId"`
	Comment    string `json:"comment" form:"comment"`
	Reset      int    `json:"reset" form:"reset"`
}
