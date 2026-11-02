package job

import "x-ui/web/service"

// OutboundCertJob has Xray restarted when a server whose certificate the panel
// pins presents a new one.
type OutboundCertJob struct {
	xrayService service.XrayService
}

func NewOutboundCertJob() *OutboundCertJob {
	return new(OutboundCertJob)
}

func (j *OutboundCertJob) Run() {
	if service.RefreshOutboundCertPins() {
		j.xrayService.SetToNeedRestart()
	}
}
