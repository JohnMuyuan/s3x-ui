package amneziawg

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"x-ui/logger"
)

type running struct {
	dev       *device.Device
	inst      Instance
	structure string
	peers     map[string]string // public key to its applied UAPI text
	emails    map[string]string // public key to client email
	last      map[string]counters
}

func (r *running) alive() bool {
	select {
	case <-r.dev.Wait():
		return false
	default:
		return true
	}
}

type Manager struct {
	mu      sync.Mutex
	devices map[int]*running
}

var manager = &Manager{devices: map[int]*running{}}

func GetManager() *Manager {
	return manager
}

// Reconcile closes the devices no longer wanted, starts or rebuilds the
// rest, and applies peer changes live.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[int]bool{}
	for _, inst := range desired {
		want[inst.Id] = true
	}
	for id, r := range m.devices {
		if !want[id] {
			m.stop(id, r)
		}
	}
	for _, inst := range desired {
		if err := m.ensure(inst); err != nil {
			logger.Warningf("amneziawg: inbound %d: %v", inst.Id, err)
		}
	}
}

func (m *Manager) StopAll() {
	m.Reconcile(nil)
}

func (m *Manager) stop(id int, r *running) {
	r.dev.Close()
	nat(r.inst, false)
	delete(m.devices, id)
	logger.Infof("amneziawg: stopped %s", r.inst.Iface)
}

func (m *Manager) ensure(inst Instance) error {
	if r, ok := m.devices[inst.Id]; ok {
		if r.alive() && r.structure == inst.structure() {
			return r.setPeers(inst)
		}
		m.stop(inst.Id, r)
	}
	// a device of a killed panel leaves no interface, but be sure
	_ = exec.Command("ip", "link", "del", inst.Iface).Run()
	tdev, err := tun.CreateTUN(inst.Iface, inst.MTU)
	if err != nil {
		return fmt.Errorf("creating %s: %w", inst.Iface, err)
	}
	prefix := fmt.Sprintf("AWG %s: ", inst.Iface)
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { logger.Warningf(prefix+format, args...) },
	})
	r := &running{dev: dev, inst: inst, structure: inst.structure(), peers: map[string]string{},
		emails: map[string]string{}, last: map[string]counters{}}
	if err := dev.IpcSet(inst.deviceConfig()); err != nil {
		dev.Close()
		return fmt.Errorf("configuring %s: %w", inst.Iface, err)
	}
	if err := r.setPeers(inst); err != nil {
		dev.Close()
		return err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bringing up %s: %w", inst.Iface, err)
	}
	for _, args := range [][]string{
		{"addr", "replace", inst.Address.String(), "dev", inst.Iface},
		{"link", "set", inst.Iface, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
	}
	nat(inst, true)
	m.devices[inst.Id] = r
	logger.Infof("amneziawg: started %s on UDP %d", inst.Iface, inst.Port)
	return nil
}

func (r *running) setPeers(inst Instance) error {
	r.inst = inst
	diff := peersDiff(r.peers, inst.Peers)
	if diff == "" {
		return nil
	}
	if err := r.dev.IpcSet(diff); err != nil {
		return fmt.Errorf("updating peers: %w", err)
	}
	r.peers, r.emails = map[string]string{}, map[string]string{}
	for _, p := range inst.Peers {
		r.peers[p.PublicKey] = p.config()
		r.emails[p.PublicKey] = p.Email
	}
	return nil
}

// nat lets the clients' subnet out through the server, adding or removing
// the forwarding and masquerade rules, marked with the interface name.
func nat(inst Instance, add bool) {
	if add {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			logger.Warning("amneziawg: enabling IPv4 forwarding:", err)
		}
	}
	comment := []string{"-m", "comment", "--comment", "s3x-" + inst.Iface}
	subnet := inst.Address.Masked().String()
	rules := []struct {
		table, chain string
		spec         []string
	}{
		{"nat", "POSTROUTING", []string{"-s", subnet, "!", "-o", inst.Iface, "-j", "MASQUERADE"}},
		{"filter", "FORWARD", []string{"-i", inst.Iface, "-j", "ACCEPT"}},
		{"filter", "FORWARD", []string{"-o", inst.Iface, "-j", "ACCEPT"}},
	}
	for _, rule := range rules {
		command := func(op string) []string {
			return slices.Concat([]string{"-t", rule.table, op, rule.chain}, rule.spec, comment)
		}
		exists := exec.Command("iptables", command("-C")...).Run() == nil
		var args []string
		switch {
		case add && !exists:
			// FORWARD rules go first, ahead of a DROP policy such as Docker's
			if rule.chain == "FORWARD" {
				args = command("-I")
			} else {
				args = command("-A")
			}
		case !add && exists:
			args = command("-D")
		default:
			continue
		}
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			logger.Warningf("amneziawg: iptables %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
	}
}

// CollectTraffic returns each client's traffic since the previous call.
func (m *Manager) CollectTraffic() []Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Traffic
	for _, r := range m.devices {
		if !r.alive() {
			continue
		}
		uapi, err := r.dev.IpcGet()
		if err != nil {
			continue
		}
		now := parseStats(uapi)
		for key, c := range now {
			email := r.emails[key]
			if email == "" {
				continue
			}
			prev := r.last[key]
			up, down := max(c.rx-prev.rx, 0), max(c.tx-prev.tx, 0)
			if up > 0 || down > 0 {
				out = append(out, Traffic{Tag: r.inst.Tag, Email: email, Up: up, Down: down})
			}
		}
		r.last = now
	}
	return out
}
