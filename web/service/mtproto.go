package service

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"x-ui/logger"
	"x-ui/mtproto"
	"x-ui/singbox"
	"x-ui/xray"
)

// mtSkipped remembers each inbound's problems, to log them once.
var mtSkipped = map[string]string{}

type MtprotoService struct {
	inboundService InboundService
	settingService SettingService
}

// Apply runs one mtg per enabled mtproto inbound. Like sbcore, mtg reaches
// Telegram through Xray unless sing-box egress is set to direct.
func (s *MtprotoService) Apply() error {
	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return err
	}
	egress, err := s.settingService.GetSingboxEgress()
	if err != nil {
		return err
	}
	var desired []mtproto.Instance
	for _, ib := range inbounds {
		// mtg logs in to Xray's bridge as its inbound, for Xray's routing.
		proxy := ""
		if egress == singbox.EgressXray {
			proxy = fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", url.PathEscape(ib.Tag), singbox.BridgePassword, singbox.BridgePort)
		}
		inst, problems, ok := mtproto.FromInbound(ib, proxy)
		if joined := strings.Join(problems, "; "); joined != mtSkipped[ib.Tag] {
			if joined != "" {
				logger.Warning("mtproto: inbound", ib.Tag+":", joined)
			}
			mtSkipped[ib.Tag] = joined
		}
		if ok {
			desired = append(desired, inst)
		}
	}
	if len(desired) > 0 {
		if _, err := os.Stat(mtproto.GetBinaryPath()); err != nil {
			return fmt.Errorf("mtg binary missing: %w", err)
		}
		ensureXrayBridge(egress)
	}
	mtproto.GetManager().Reconcile(desired)
	return nil
}

func (s *MtprotoService) GetTraffic() ([]*xray.Traffic, []*xray.ClientTraffic) {
	inbounds := map[string]*xray.Traffic{}
	var clients []*xray.ClientTraffic
	for _, t := range mtproto.GetManager().CollectTraffic() {
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
