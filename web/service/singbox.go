package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"x-ui/logger"
	"x-ui/singbox"
	"x-ui/xray"
)

var (
	sbProcess *singbox.Process
	sbLock    sync.Mutex
	// sbApplied mirrors what sbcore runs: inbound tag to its JSON, plus the
	// config around the inbounds. nil means unknown, forcing a full start.
	sbApplied  map[string]string
	sbBase     string
	sbApplyCh  = make(chan struct{}, 1)
	sbNoBinary bool
)

type SingboxService struct {
	inboundService InboundService
	settingService SettingService
}

// RequestSingboxApply schedules a reconcile of sbcore with the database. It
// never blocks, so callers inside a DB transaction can use it safely.
func RequestSingboxApply() {
	select {
	case sbApplyCh <- struct{}{}:
	default:
	}
}

// StartSingboxApplier debounces apply requests; the delay lets the caller's
// transaction commit before the database is read.
func StartSingboxApplier(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sbApplyCh:
			}
			time.Sleep(300 * time.Millisecond)
			if err := new(SingboxService).Apply(); err != nil {
				logger.Warning("sbcore apply failed:", err)
			}
		}
	}()
}

type sbDesired struct {
	egress   string
	base     string
	inbounds map[string]string
	order    []string
}

func (s *SingboxService) desired() (*sbDesired, error) {
	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	d := &sbDesired{inbounds: map[string]string{}}
	for _, ib := range inbounds {
		if !ib.Enable || !ib.Protocol.IsSingbox() {
			continue
		}
		parts, err := singbox.BuildInbounds(ib)
		if err != nil {
			logger.Warning("sbcore: skipping inbound:", err)
			continue
		}
		for _, part := range parts {
			raw, err := json.Marshal(part)
			if err != nil {
				return nil, err
			}
			tag, _ := part["tag"].(string)
			d.inbounds[tag] = string(raw)
			d.order = append(d.order, tag)
		}
	}
	egress, err := s.settingService.GetSingboxEgress()
	if err != nil {
		return nil, err
	}
	d.egress = egress
	base := singbox.BuildConfig(nil, egress, "warn")
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	d.base = string(raw)
	return d, nil
}

func fullConfig(d *sbDesired) ([]byte, error) {
	cfg := map[string]any{}
	if err := json.Unmarshal([]byte(d.base), &cfg); err != nil {
		return nil, err
	}
	inbounds := make([]json.RawMessage, 0, len(d.order))
	for _, tag := range d.order {
		inbounds = append(inbounds, json.RawMessage(d.inbounds[tag]))
	}
	cfg["inbounds"] = inbounds
	return json.Marshal(cfg)
}

// Apply brings sbcore in line with the database: started only while some
// sing-box inbound is enabled, and changed inbound by inbound when possible.
func (s *SingboxService) Apply() error {
	sbLock.Lock()
	defer sbLock.Unlock()

	d, err := s.desired()
	if err != nil {
		return err
	}
	if len(d.inbounds) == 0 {
		if sbProcess != nil {
			logger.Info("sbcore: no sing-box inbounds, stopping")
			err = sbProcess.Stop()
			sbProcess, sbApplied = nil, nil
		}
		return err
	}
	if _, statErr := os.Stat(singbox.GetBinaryPath()); statErr != nil {
		if !sbNoBinary {
			logger.Error("sbcore binary missing, sing-box inbounds are not served:", singbox.GetBinaryPath())
			sbNoBinary = true
		}
		return nil
	}
	sbNoBinary = false

	if sbProcess == nil || !sbProcess.IsRunning() {
		if sbProcess != nil {
			logger.Warning("sbcore is not running, restarting:", sbProcess.Result())
		}
		sbProcess, sbApplied = singbox.NewProcess(), nil
		if err = sbProcess.Start(); err != nil {
			sbProcess = nil
			return err
		}
	}
	api := sbProcess.API()
	ensureXrayBridge(d.egress)

	if sbApplied == nil || d.base != sbBase {
		return startFull(api, d)
	}
	if err = applyDiff(api, d); err != nil {
		logger.Warning("sbcore: incremental apply failed, reloading all inbounds:", err)
		return startFull(api, d)
	}
	return nil
}

func startFull(api *singbox.API, d *sbDesired) error {
	cfg, err := fullConfig(d)
	if err != nil {
		return err
	}
	if err = api.Start(cfg); err != nil {
		sbApplied = nil
		return err
	}
	sbApplied, sbBase = d.inbounds, d.base
	logger.Infof("sbcore: started with %d inbound(s)", len(d.inbounds))
	return nil
}

func applyDiff(api *singbox.API, d *sbDesired) error {
	for tag := range sbApplied {
		if _, keep := d.inbounds[tag]; !keep {
			if err := api.DelInbound(tag); err != nil {
				return err
			}
			delete(sbApplied, tag)
		}
	}
	// Reverse order adds ShadowTLS's inner inbound before the front detouring to it.
	for i := len(d.order) - 1; i >= 0; i-- {
		tag := d.order[i]
		want := d.inbounds[tag]
		have, live := sbApplied[tag]
		switch {
		case !live:
			if err := api.AddInbound([]byte(want)); err != nil {
				return err
			}
		case have == want:
			continue
		case sameExceptUsers(have, want):
			hot, err := api.UpdateUsers([]byte(want))
			if err != nil {
				return err
			}
			if !hot {
				if err = replaceInbound(api, tag, want); err != nil {
					return err
				}
			}
		default:
			if err := replaceInbound(api, tag, want); err != nil {
				return err
			}
		}
		sbApplied[tag] = want
	}
	return nil
}

// ensureXrayBridge hot-adds the bridge inbound when sbcore starts egressing
// through an Xray that was started before any sing-box inbound existed.
func ensureXrayBridge(egress string) {
	if egress != singbox.EgressXray || p == nil || !p.IsRunning() {
		return
	}
	running := p.GetConfig()
	for _, ib := range running.InboundConfigs {
		if ib.Tag == singbox.BridgeTag {
			return
		}
	}
	bridge, err := singboxBridgeInbound()
	if err == nil {
		var raw []byte
		if raw, err = json.Marshal(bridge); err == nil {
			var api xray.XrayAPI
			if err = api.Init(p.GetAPIPort()); err == nil {
				err = api.AddInbound(raw)
				api.Close()
			}
		}
	}
	if err != nil {
		logger.Warning("sbcore: adding Xray bridge inbound failed, restarting Xray:", err)
		new(XrayService).SetToNeedRestart()
		return
	}
	// Keep the recorded config in step so the next restart check sees no change.
	running.InboundConfigs = append(running.InboundConfigs, *bridge)
}

func replaceInbound(api *singbox.API, tag, want string) error {
	if err := api.DelInbound(tag); err != nil {
		return err
	}
	return api.AddInbound([]byte(want))
}

func sameExceptUsers(a, b string) bool {
	var ma, mb map[string]any
	if json.Unmarshal([]byte(a), &ma) != nil || json.Unmarshal([]byte(b), &mb) != nil {
		return false
	}
	delete(ma, "users")
	delete(mb, "users")
	return reflect.DeepEqual(ma, mb)
}

func (s *SingboxService) IsRunning() bool {
	sbLock.Lock()
	defer sbLock.Unlock()
	return sbProcess != nil && sbProcess.IsRunning()
}

// NeedsRestart reports a sidecar that should be up but died.
func (s *SingboxService) NeedsRestart() bool {
	sbLock.Lock()
	defer sbLock.Unlock()
	return sbProcess != nil && !sbProcess.IsRunning()
}

func (s *SingboxService) Stop() error {
	sbLock.Lock()
	defer sbLock.Unlock()
	if sbProcess == nil {
		return nil
	}
	err := sbProcess.Stop()
	sbProcess, sbApplied = nil, nil
	return err
}

func runningAPI() (*singbox.API, error) {
	sbLock.Lock()
	defer sbLock.Unlock()
	if sbProcess == nil || !sbProcess.IsRunning() || sbApplied == nil {
		return nil, errors.New("sbcore is not running")
	}
	return sbProcess.API(), nil
}

// GetTraffic drains sbcore's counters into Xray's traffic types so the
// existing accounting, limits and online tracking apply unchanged.
func (s *SingboxService) GetTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	api, err := runningAPI()
	if err != nil {
		return nil, nil, err
	}
	stats, err := api.Stats()
	if err != nil {
		return nil, nil, err
	}
	inbounds := map[string]*xray.Traffic{}
	clients := map[string]*xray.ClientTraffic{}
	for _, st := range stats {
		switch st.Resource {
		case "inbound":
			t := inbounds[st.Tag]
			if t == nil {
				t = &xray.Traffic{IsInbound: true, Tag: st.Tag}
				inbounds[st.Tag] = t
			}
			if st.Direction {
				t.Up += st.Traffic
			} else {
				t.Down += st.Traffic
			}
		case "user":
			c := clients[st.Tag]
			if c == nil {
				c = &xray.ClientTraffic{Email: st.Tag}
				clients[st.Tag] = c
			}
			if st.Direction {
				c.Up += st.Traffic
			} else {
				c.Down += st.Traffic
			}
		}
	}
	traffics := make([]*xray.Traffic, 0, len(inbounds))
	for _, t := range inbounds {
		traffics = append(traffics, t)
	}
	clientTraffics := make([]*xray.ClientTraffic, 0, len(clients))
	for _, c := range clients {
		clientTraffics = append(clientTraffics, c)
	}
	return traffics, clientTraffics, nil
}

func (s *SingboxService) GetSessions() ([]singbox.Session, error) {
	api, err := runningAPI()
	if err != nil {
		return nil, err
	}
	return api.Sessions()
}
