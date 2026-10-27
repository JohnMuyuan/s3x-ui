//go:build !linux

package amneziawg

// AmneziaWG needs Linux TUN and iptables; elsewhere nothing runs.
type Manager struct{}

var manager = &Manager{}

func GetManager() *Manager { return manager }

func (m *Manager) Reconcile([]Instance) {}

func (m *Manager) StopAll() {}

func (m *Manager) CollectTraffic() []Traffic { return nil }
