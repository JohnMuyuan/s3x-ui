package mtproto

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"x-ui/config"
	"x-ui/logger"
)

func GetBinaryName() string {
	return fmt.Sprintf("mtg-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

func configDir() string {
	return config.GetBinFolderPath() + "/mtproto"
}

func configPath(id int) string {
	return fmt.Sprintf("%s/mtg-%d.toml", configDir(), id)
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *process) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *process) stop() {
	if !p.running() {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

func start(id int) (*process, error) {
	cmd := exec.Command(GetBinaryPath(), "run", configPath(id))
	out, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = cmd.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go pipeLog(id, out)
	go func() {
		err := cmd.Wait()
		close(p.done)
		if err != nil {
			logger.Warningf("mtg for inbound %d exited: %v", id, err)
		}
	}()
	return p, nil
}

func pipeLog(id int, r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			logger.Infof("MTG %d: %s", id, line)
		}
	}
}

type counters struct{ up, down int64 }

type managed struct {
	proc      *process
	tag       string
	structure string
	secrets   string
	apiPort   int
	apiToken  string
	last      map[string]counters
}

// Manager owns the running mtg processes, keyed by inbound id.
type Manager struct {
	mu    sync.Mutex
	procs map[int]*managed
	swept bool
}

var manager = &Manager{procs: map[int]*managed{}}

func GetManager() *Manager {
	return manager
}

// Reconcile stops the mtg processes no longer wanted and starts, restarts or
// updates the rest. Dead processes are started again.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.swept {
		// mtg outlives a killed panel; a leftover would hold the port.
		m.swept = true
		if n := killStray(GetBinaryName()); n > 0 {
			logger.Warningf("mtproto: killed %d mtg left from a previous run", n)
		}
	}
	want := map[int]bool{}
	for _, inst := range desired {
		want[inst.Id] = true
	}
	for id, cur := range m.procs {
		if !want[id] {
			cur.proc.stop()
			delete(m.procs, id)
			os.Remove(configPath(id))
			logger.Infof("mtproto: stopped mtg for inbound %d", id)
		}
	}
	for _, inst := range desired {
		if err := m.ensure(inst); err != nil {
			logger.Warningf("mtproto: inbound %d: %v", inst.Id, err)
		}
	}
}

func (m *Manager) ensure(inst Instance) error {
	structure, secrets := inst.structure(), inst.secrets()
	if cur, ok := m.procs[inst.Id]; ok {
		cur.tag = inst.Tag
		if cur.proc.running() && cur.structure == structure {
			if cur.secrets == secrets {
				return nil
			}
			if err := writeConfig(inst, cur.apiPort, cur.apiToken); err != nil {
				return err
			}
			if putSecrets(cur.apiPort, cur.apiToken, inst) {
				cur.secrets = secrets
				return nil
			}
			logger.Warningf("mtproto: live update of inbound %d failed, restarting mtg", inst.Id)
		}
		cur.proc.stop()
		delete(m.procs, inst.Id)
	}
	apiPort, err := freePort()
	if err != nil {
		return err
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	apiToken := hex.EncodeToString(token)
	if err := writeConfig(inst, apiPort, apiToken); err != nil {
		return err
	}
	proc, err := start(inst.Id)
	if err != nil {
		return err
	}
	m.procs[inst.Id] = &managed{proc: proc, tag: inst.Tag, structure: structure, secrets: secrets,
		apiPort: apiPort, apiToken: apiToken, last: map[string]counters{}}
	logger.Infof("mtproto: started mtg for inbound %d on %s", inst.Id, inst.bindTo())
	return nil
}

func (m *Manager) StopAll() {
	m.Reconcile(nil)
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cur := range m.procs {
		if cur.proc.running() {
			return true
		}
	}
	return false
}

// Traffic is the bytes one client moved since the last collection.
type Traffic struct {
	Tag, Email string
	Up, Down   int64
}

// CollectTraffic returns each client's traffic since the previous call; a
// new or restarted mtg counts from zero.
func (m *Manager) CollectTraffic() []Traffic {
	type target struct {
		id, port   int
		token, tag string
		last       map[string]counters
	}
	m.mu.Lock()
	targets := make([]target, 0, len(m.procs))
	for id, cur := range m.procs {
		if cur.proc.running() {
			targets = append(targets, target{id, cur.apiPort, cur.apiToken, cur.tag, cur.last})
		}
	}
	m.mu.Unlock()

	var out []Traffic
	for _, t := range targets {
		users, ok := stats(t.port, t.token)
		if !ok {
			continue
		}
		now := make(map[string]counters, len(users))
		for email, u := range users {
			now[email] = counters{u.BytesIn, u.BytesOut}
			prev := t.last[email]
			up, down := max(u.BytesIn-prev.up, 0), max(u.BytesOut-prev.down, 0)
			if up > 0 || down > 0 {
				out = append(out, Traffic{Tag: t.tag, Email: email, Up: up, Down: down})
			}
		}
		m.mu.Lock()
		if cur, ok := m.procs[t.id]; ok && cur.apiPort == t.port {
			cur.last = now
		}
		m.mu.Unlock()
	}
	return out
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
