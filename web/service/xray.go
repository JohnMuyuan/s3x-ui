package service

import (
	"encoding/json"
	"errors"
	"sync"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/singbox"
	"x-ui/util/json_util"
	"x-ui/xray"

	"go.uber.org/atomic"
)

var (
	p                 *xray.Process
	lock              sync.Mutex
	isNeedXrayRestart atomic.Bool
	result            string
)

type XrayService struct {
	inboundService InboundService
	settingService SettingService
	xrayAPI        xray.XrayAPI
}

func (s *XrayService) IsXrayRunning() bool {
	return p != nil && p.IsRunning()
}

func (s *XrayService) GetXrayErr() error {
	if p == nil {
		return nil
	}
	return p.GetErr()
}

func (s *XrayService) GetXrayResult() string {
	if result != "" {
		return result
	}
	if s.IsXrayRunning() {
		return ""
	}
	if p == nil {
		return ""
	}
	result = p.GetResult()
	return result
}

func (s *XrayService) GetXrayVersion() string {
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

func RemoveIndex(s []any, index int) []any {
	return append(s[:index], s[index+1:]...)
}

func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}
	xrayConfig.OutboundConfigs = dropAllowInsecure(xrayConfig.OutboundConfigs)
	xrayConfig.Policy = withUserOnline(xrayConfig.Policy)

	s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	hasSingbox := false
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if inbound.Protocol.IsSidecar() {
			hasSingbox = true
			continue
		}
		inboundConfig, err := XrayInboundConfig(inbound)
		if err != nil {
			// One inbound Xray refuses must not stop all the others.
			logger.Warning("skipping inbound:", err)
			continue
		}
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}
	if hasSingbox {
		egress, err := s.settingService.GetSingboxEgress()
		if err != nil {
			return nil, err
		}
		if egress == singbox.EgressXray {
			bridge, err := singboxBridgeInbound()
			if err != nil {
				return nil, err
			}
			xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *bridge)
		}
	}
	if target, err := s.settingService.GetPanelOutbound(); err == nil && target != "" {
		injectPanelEgress(xrayConfig, target)
	}
	injectOutboundProbe(xrayConfig)
	return xrayConfig, nil
}

func singboxBridgeInbound() (*xray.InboundConfig, error) {
	b := singbox.BridgeInbound()
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

func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	if !s.IsXrayRunning() {
		err := errors.New("xray is not running")
		logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
		return nil, nil, err
	}
	apiPort := p.GetAPIPort()
	s.xrayAPI.Init(apiPort)
	defer s.xrayAPI.Close()

	traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
	if err != nil {
		logger.Debug("Failed to fetch Xray traffic:", err)
		return nil, nil, err
	}
	return traffic, clientTraffic, nil
}

func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("restart xray, force:", isForce)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	if s.IsXrayRunning() {
		if !isForce && p.GetConfig().Equals(xrayConfig) {
			logger.Debug("It does not need to restart xray")
			RequestSingboxApply()
			return nil
		}
		p.Stop()
	}

	p = xray.NewProcess(xrayConfig)
	result = ""
	err = p.Start()
	RequestSingboxApply()
	if err != nil {
		return err
	}
	return nil
}

func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("Attempting to stop Xray...")
	if s.IsXrayRunning() {
		return p.Stop()
	}
	return errors.New("xray is not running")
}

func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CompareAndSwap(true, false)
}

// XrayInboundConfig turns a stored inbound into what Xray runs: disabled
// clients and panel-only fields removed, and settings older panels saved
// rewritten for Xray 26. Both the full config and the API hot-add paths use
// it; the inbound itself is left untouched.
func XrayInboundConfig(stored *model.Inbound) (*xray.InboundConfig, error) {
	if err := unrunnable(stored); err != nil {
		return nil, err
	}
	copied := *stored
	inbound := &copied
	// get settings clients
	settings := map[string]any{}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	clients, ok := settings["clients"].([]any)
	if ok {
		// check users active or not
		clientStats := inbound.ClientStats
		for _, clientTraffic := range clientStats {
			indexDecrease := 0
			for index, client := range clients {
				c := client.(map[string]any)
				if c["email"] == clientTraffic.Email {
					if !clientTraffic.Enable {
						clients = RemoveIndex(clients, index-indexDecrease)
						indexDecrease++
						logger.Infof("Remove Inbound User %s due to expiration or traffic limit", c["email"])
					}
				}
			}
		}

		// clear client config for additional parameters
		var final_clients []any
		for _, client := range clients {
			c := client.(map[string]any)
			if c["enable"] != nil {
				if enable, ok := c["enable"].(bool); ok && !enable {
					continue
				}
			}
			for key := range c {
				if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" {
					delete(c, key)
				}
				if c["flow"] == "xtls-rprx-vision-udp443" {
					c["flow"] = "xtls-rprx-vision"
				}
			}
			if inbound.Protocol == model.MASQUE {
				// MASQUE users log in with HTTP Basic auth, which Xray calls pass.
				c["pass"] = c["password"]
				delete(c, "password")
			}
			final_clients = append(final_clients, any(c))
		}

		settings["clients"] = final_clients
		// Xray refuses fallbacks, even an empty list, next to VLESS encryption;
		// the client half of the key pair is only for share links.
		if dec, _ := settings["decryption"].(string); dec != "" && dec != "none" {
			delete(settings, "fallbacks")
		}
		delete(settings, "encryption")
		modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return nil, err
		}

		inbound.Settings = string(modifiedSettings)
	}

	if len(inbound.StreamSettings) > 0 {
		// Unmarshal stream JSON
		var stream map[string]any
		json.Unmarshal([]byte(inbound.StreamSettings), &stream)

		// Remove the "settings" field under "tlsSettings" and "realitySettings"
		tlsSettings, ok1 := stream["tlsSettings"].(map[string]any)
		realitySettings, ok2 := stream["realitySettings"].(map[string]any)
		if ok1 || ok2 {
			if ok1 {
				delete(tlsSettings, "settings")
			} else if ok2 {
				delete(realitySettings, "settings")
			}
		}

		delete(stream, "externalProxy")
		kcpLegacyToFinalmask(stream)

		newStream, err := json.MarshalIndent(stream, "", "  ")
		if err != nil {
			return nil, err
		}
		inbound.StreamSettings = string(newStream)
	}

	return inbound.GenXrayInboundConfig(), nil
}
