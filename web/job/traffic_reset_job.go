package job

import (
	"time"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/web/service"
	"x-ui/xray"
)

// TrafficResetJob zeroes the traffic of inbounds whose reset period has
// begun since their last reset, so a reset missed while the panel was down
// still happens once it is back.
type TrafficResetJob struct {
	inboundService service.InboundService
	xrayService    service.XrayService
}

func NewTrafficResetJob() *TrafficResetJob {
	return new(TrafficResetJob)
}

// periodStart is when the period containing now began: the hour, the day,
// Monday, or the reset day of the month (the month's last day if shorter).
func periodStart(period string, day int, now time.Time) (time.Time, bool) {
	y, m, d := now.Date()
	loc := now.Location()
	switch period {
	case "hourly":
		return now.Truncate(time.Hour), true
	case "daily":
		return time.Date(y, m, d, 0, 0, 0, 0, loc), true
	case "weekly":
		back := (int(now.Weekday()) + 6) % 7
		return time.Date(y, m, d-back, 0, 0, 0, 0, loc), true
	case "monthly":
		at := func(y int, m time.Month) time.Time {
			last := time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()
			return time.Date(y, m, min(max(day, 1), last), 0, 0, 0, 0, loc)
		}
		if start := at(y, m); !now.Before(start) {
			return start, true
		}
		return at(y, m-1), true
	}
	return time.Time{}, false
}

func (j *TrafficResetJob) Run() {
	var inbounds []*model.Inbound
	db := database.GetDB()
	if err := db.Where("traffic_reset IS NOT NULL AND traffic_reset NOT IN ?", []string{"", "never"}).Find(&inbounds).Error; err != nil {
		logger.Warning("traffic reset: listing inbounds:", err)
		return
	}
	now := time.Now()
	needRestart := false
	for _, ib := range inbounds {
		start, ok := periodStart(ib.TrafficReset, ib.TrafficResetDay, now)
		if !ok || ib.LastTrafficResetTime >= start.UnixMilli() {
			continue
		}
		var disabled int64
		db.Model(xray.ClientTraffic{}).Where("inbound_id = ? AND enable = ?", ib.Id, false).Count(&disabled)
		// an inbound its own traffic cap switched off comes back with the reset
		quotaOff := !ib.Enable && ib.Total > 0 && ib.Up+ib.Down >= ib.Total && (ib.ExpiryTime <= 0 || ib.ExpiryTime > now.UnixMilli())
		updates := map[string]any{"up": 0, "down": 0, "last_traffic_reset_time": now.UnixMilli()}
		if quotaOff {
			updates["enable"] = true
		}
		if err := db.Model(model.Inbound{}).Where("id = ?", ib.Id).Updates(updates).Error; err != nil {
			logger.Warning("traffic reset: inbound", ib.Id, err)
			continue
		}
		if err := j.inboundService.ResetAllClientTraffics(ib.Id); err != nil {
			logger.Warning("traffic reset: clients of inbound", ib.Id, err)
		}
		logger.Infof("traffic reset (%s): inbound %d %q", ib.TrafficReset, ib.Id, ib.Remark)
		if quotaOff || disabled > 0 {
			needRestart = true
		}
	}
	if needRestart {
		// re-enabled clients and inbounds have to be added back to the cores
		j.xrayService.SetToNeedRestart()
	}
}
