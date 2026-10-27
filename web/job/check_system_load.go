package job

import (
	"strconv"
	"time"

	"x-ui/web/service"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

// CheckSystemLoadJob alerts the Telegram admins when CPU or memory use stays
// over its threshold. It runs every minute; the CPU figure is the average
// since the last run.
type CheckSystemLoadJob struct {
	tgbotService   service.Tgbot
	settingService service.SettingService
	cpuAlert       thresholdAlert
	memAlert       thresholdAlert
}

func NewCheckSystemLoadJob() *CheckSystemLoadJob {
	job := new(CheckSystemLoadJob)
	cpu.Percent(0, false) // the first call only starts the count
	return job
}

func (j *CheckSystemLoadJob) Run() {
	if percent, err := cpu.Percent(0, false); err == nil && len(percent) > 0 {
		threshold, _ := j.settingService.GetTgCpu()
		if j.cpuAlert.due(threshold > 0 && percent[0] > float64(threshold)) {
			j.tgbotService.NotifyEvent(service.TgEventCPU, j.tgbotService.I18nBot("tgbot.messages.cpuThreshold",
				"Percent=="+strconv.FormatFloat(percent[0], 'f', 2, 64), "Threshold=="+strconv.Itoa(threshold)))
		}
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		threshold, _ := j.settingService.GetTgMemory()
		if j.memAlert.due(threshold > 0 && vm.UsedPercent > float64(threshold)) {
			j.tgbotService.NotifyEvent(service.TgEventMemory, j.tgbotService.I18nBot("tgbot.messages.memoryThreshold",
				"Percent=="+strconv.FormatFloat(vm.UsedPercent, 'f', 2, 64), "Threshold=="+strconv.Itoa(threshold)))
		}
	}
}

// thresholdAlert lets an alert go out when a value goes over its threshold,
// and again only after half an hour over it, or once it went back under.
type thresholdAlert struct {
	over   bool
	sentAt time.Time
}

func (a *thresholdAlert) due(over bool) bool {
	if !over {
		a.over = false
		return false
	}
	if a.over && time.Since(a.sentAt) < 30*time.Minute {
		return false
	}
	a.over, a.sentAt = true, time.Now()
	return true
}
