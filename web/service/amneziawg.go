package service

import (
	"strings"

	"x-ui/amneziawg"
	"x-ui/logger"
	"x-ui/xray"
)

// awgSkipped remembers each inbound's problems, to log them once.
var awgSkipped = map[string]string{}

type AmneziaWGService struct {
	inboundService InboundService
}

func (s *AmneziaWGService) Apply() error {
	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return err
	}
	var desired []amneziawg.Instance
	for _, ib := range inbounds {
		inst, problems, ok := amneziawg.FromInbound(ib)
		if joined := strings.Join(problems, "; "); joined != awgSkipped[ib.Tag] {
			if joined != "" {
				logger.Warning("amneziawg: inbound", ib.Tag+":", joined)
			}
			awgSkipped[ib.Tag] = joined
		}
		if ok {
			desired = append(desired, inst)
		}
	}
	amneziawg.GetManager().Reconcile(desired)
	return nil
}

func (s *AmneziaWGService) GetTraffic() ([]*xray.Traffic, []*xray.ClientTraffic) {
	inbounds := map[string]*xray.Traffic{}
	var clients []*xray.ClientTraffic
	for _, t := range amneziawg.GetManager().CollectTraffic() {
		in := inbounds[t.Tag]
		if in == nil {
			in = &xray.Traffic{IsInbound: true, Tag: t.Tag}
			inbounds[t.Tag] = in
		}
		in.Up += t.Up
		in.Down += t.Down
		clients = append(clients, &xray.ClientTraffic{Email: t.Email, Up: t.Up, Down: t.Down})
	}
	traffics := make([]*xray.Traffic, 0, len(inbounds))
	for _, t := range inbounds {
		traffics = append(traffics, t)
	}
	return traffics, clients
}
