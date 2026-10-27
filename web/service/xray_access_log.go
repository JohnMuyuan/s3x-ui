package service

import (
	"encoding/json"
	"strings"
)

// accessLogPath is where a switched-on access log goes, beside the Xray
// binary, as in the Xray settings' log section.
const accessLogPath = "./access.log"

// AccessLogEnabled reports whether the Xray template writes an access log.
func (s *XrayService) AccessLogEnabled() (bool, error) {
	cfg, err := s.templateMap()
	if err != nil {
		return false, err
	}
	logCfg, _ := cfg["log"].(map[string]any)
	path, _ := logCfg["access"].(string)
	path = strings.TrimSpace(path)
	return path != "" && path != "none", nil
}

// SetAccessLog switches Xray's access log on or off in the template and
// restarts Xray to apply it. Client IP limits read this log.
func (s *XrayService) SetAccessLog(enable bool) error {
	if on, err := s.AccessLogEnabled(); err != nil || on == enable {
		return err
	}
	cfg, err := s.templateMap()
	if err != nil {
		return err
	}
	logCfg, _ := cfg["log"].(map[string]any)
	if logCfg == nil {
		logCfg = map[string]any{}
		cfg["log"] = logCfg
	}
	if enable {
		logCfg["access"] = accessLogPath
	} else {
		logCfg["access"] = "none"
	}
	tmpl, err := marshalTemplate(cfg)
	if err != nil {
		return err
	}
	if err := s.settingService.saveSetting("xrayTemplateConfig", tmpl); err != nil {
		return err
	}
	return s.RestartXray(false)
}

func (s *XrayService) templateMap() (map[string]any, error) {
	tmpl, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	return cfg, json.Unmarshal([]byte(tmpl), &cfg)
}
