package job

import (
	"strconv"
	"time"

	"x-ui/logger"
	"x-ui/web/service"
)

// OutboundMonitorJob tests every outbound at the set interval. An outbound
// failing twice in a row is reported down to the Telegram admins once, and
// reported again when it works.
type OutboundMonitorJob struct {
	settingService service.SettingService
	tgbotService   service.Tgbot
	lastRun        time.Time
	fails          map[string]int
	down           map[string]bool
}

func NewOutboundMonitorJob() *OutboundMonitorJob {
	return &OutboundMonitorJob{fails: map[string]int{}, down: map[string]bool{}}
}

func (j *OutboundMonitorJob) Run() {
	if enable, err := j.settingService.GetOutboundMonitorEnable(); err != nil || !enable {
		return
	}
	interval, _ := j.settingService.GetOutboundMonitorInterval()
	if time.Since(j.lastRun) < time.Duration(max(interval, 1))*time.Minute-5*time.Second {
		return
	}
	j.lastRun = time.Now()
	testURL, _ := j.settingService.GetOutboundTestUrl()
	for _, r := range service.ProbeAllOutbounds(testURL) {
		if r.OK {
			j.fails[r.Tag] = 0
			if j.down[r.Tag] {
				delete(j.down, r.Tag)
				j.alert(j.tgbotService.I18nBot("tgbot.messages.outboundUp", "Tag=="+r.Tag, "Delay=="+strconv.Itoa(r.DelayMs)))
			}
			continue
		}
		j.fails[r.Tag]++
		if j.fails[r.Tag] == 2 && !j.down[r.Tag] {
			j.down[r.Tag] = true
			logger.Warningf("outbound %s is down: %s", r.Tag, r.Error)
			j.alert(j.tgbotService.I18nBot("tgbot.messages.outboundDown", "Tag=="+r.Tag, "Error=="+r.Error))
		}
	}
}

func (j *OutboundMonitorJob) alert(msg string) {
	j.tgbotService.NotifyEvent(service.TgEventOutbound, msg)
}
