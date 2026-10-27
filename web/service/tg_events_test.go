package service

import (
	"path/filepath"
	"slices"
	"testing"

	"x-ui/database"
)

func TestMigrateTgNotifyEvents(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Skip("no database:", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := database.GetDB().DB(); err == nil {
			sqlDB.Close()
		}
	})
	var s SettingService
	// a 2.6.2 panel with login messages off and backups on
	s.setString("tgBotLoginNotify", "false")
	s.setString("tgBotBackup", "true")
	s.MigrateTgNotifyEvents()
	if got := s.GetTgNotifyEvents(); !slices.Equal(got, []string{"report", "cpu", "outbound", "backup"}) {
		t.Errorf("events %v", got)
	}
	// a chosen list stays, even an empty one
	s.setString("tgNotifyEvents", "")
	s.MigrateTgNotifyEvents()
	if got := s.GetTgNotifyEvents(); len(got) != 0 || s.TgEventEnabled(TgEventReport) {
		t.Errorf("a chosen empty list became %v", got)
	}
}
