package service

import (
	"slices"
	"strings"

	"x-ui/database"
	"x-ui/logger"
)

// The events the Telegram bot reports to its admins, chosen in the bot
// settings ("tgNotifyEvents", comma separated).
const (
	TgEventReport   = "report"   // the scheduled report: server usage, exhausted clients
	TgEventBackup   = "backup"   // the database with the report
	TgEventLogin    = "login"    // panel logins
	TgEventCPU      = "cpu"      // CPU over its threshold
	TgEventMemory   = "memory"   // memory over its threshold
	TgEventOutbound = "outbound" // an outbound down or back, from the monitor
	TgEventXray     = "xray"     // Xray stopped by itself and was restarted
)

func (s *SettingService) GetTgNotifyEvents() []string {
	value, _ := s.getString("tgNotifyEvents")
	var events []string
	for _, e := range strings.Split(value, ",") {
		if e = strings.TrimSpace(e); e != "" {
			events = append(events, e)
		}
	}
	return events
}

func (s *SettingService) TgEventEnabled(event string) bool {
	return slices.Contains(s.GetTgNotifyEvents(), event)
}

// MigrateTgNotifyEvents gives a panel that has no event list yet the events
// its 2.6.2 settings sent: the report, CPU and outbound alerts, and the login
// and backup messages as their switches were. The memory and Xray alerts are
// new and start off.
func (s *SettingService) MigrateTgNotifyEvents() {
	if _, err := s.getSetting("tgNotifyEvents"); !database.IsNotFound(err) {
		return
	}
	events := []string{TgEventReport, TgEventCPU, TgEventOutbound}
	if on, _ := s.GetTgBotLoginNotify(); on {
		events = append(events, TgEventLogin)
	}
	if on, _ := s.GetTgBotBackup(); on {
		events = append(events, TgEventBackup)
	}
	if err := s.setString("tgNotifyEvents", strings.Join(events, ",")); err != nil {
		logger.Warning("set the Telegram notification events:", err)
	}
}
