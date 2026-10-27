package job

import (
	"time"

	"x-ui/logger"
	"x-ui/web/service"
)

type CheckXrayRunningJob struct {
	xrayService    service.XrayService
	singboxService service.SingboxService
	tgbotService   service.Tgbot

	checkTime int
	alertedAt time.Time
}

func NewCheckXrayRunningJob() *CheckXrayRunningJob {
	return new(CheckXrayRunningJob)
}

func (j *CheckXrayRunningJob) Run() {
	if j.singboxService.NeedsRestart() {
		service.RequestSingboxApply()
	}
	if j.xrayService.IsXrayRunning() {
		j.checkTime = 0
	} else {
		j.checkTime++
		// only restart if it's down 2 times in a row
		if j.checkTime > 1 {
			exited, why := j.xrayService.XrayExited()
			err := j.xrayService.RestartXray(false)
			j.checkTime = 0
			if err != nil {
				logger.Error("Restart xray failed:", err)
			}
			// one alert per half hour, as a broken config fails every start
			if exited && time.Since(j.alertedAt) > 30*time.Minute {
				j.alertedAt = time.Now()
				msg := j.tgbotService.I18nBot("tgbot.messages.xrayStopped", "Error=="+why)
				if err != nil {
					msg = j.tgbotService.I18nBot("tgbot.messages.xrayRestartFailed", "Error=="+why, "Restart=="+err.Error())
				}
				go j.tgbotService.NotifyEvent(service.TgEventXray, msg)
			}
		}
	}
}
