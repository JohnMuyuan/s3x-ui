package job

import "x-ui/web/service"

// OutboundSubJob refreshes the outbound subscriptions that are due, and has
// Xray restarted when their nodes changed.
type OutboundSubJob struct {
	subService  service.OutboundSubscriptionService
	xrayService service.XrayService
}

func NewOutboundSubJob() *OutboundSubJob {
	return new(OutboundSubJob)
}

func (j *OutboundSubJob) Run() {
	if j.subService.RefreshDue() {
		j.xrayService.SetToNeedRestart()
	}
}
