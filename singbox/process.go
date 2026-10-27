package singbox

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

const (
	// APIPort and BridgePort sit next to Xray's 62789 API port.
	APIPort    = 62790
	BridgePort = 62791
	BridgeUser = "sbcore"
)

func GetBinaryName() string {
	return fmt.Sprintf("sbcore-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// BridgePassword authenticates sbcore on Xray's loopback bridge inbound. It
// lives for the panel process; both configs are rebuilt from it on restart.
var BridgePassword = randomToken()

type Process struct {
	cmd      *exec.Cmd
	api      *API
	done     chan struct{}
	exitErr  error
	lastLine string
	mu       sync.Mutex
}

func NewProcess() *Process {
	token := randomToken()
	return &Process{
		api:  NewAPI(fmt.Sprintf("127.0.0.1:%d", APIPort), token),
		done: make(chan struct{}),
	}
}

func (p *Process) API() *API {
	return p.api
}

func (p *Process) IsRunning() bool {
	select {
	case <-p.done:
		return false
	default:
		return p.cmd != nil
	}
}

// Result is the last log line, or the exit error when the process died silently.
func (p *Process) Result() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastLine == "" && p.exitErr != nil {
		return p.exitErr.Error()
	}
	return p.lastLine
}

// Start launches sbcore and waits until its API answers.
func (p *Process) Start() error {
	if p.cmd != nil {
		return errors.New("sbcore already started")
	}
	cmd := exec.Command(GetBinaryPath(), "-listen", fmt.Sprintf("127.0.0.1:%d", APIPort))
	cmd.Env = append(os.Environ(), "SBCORE_TOKEN="+p.api.token)
	out, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = cmd.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	p.cmd = cmd
	go p.pipeLog(out)
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		p.mu.Unlock()
		close(p.done)
		if err != nil {
			logger.Warning("sbcore exited:", err)
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !p.IsRunning() {
			return fmt.Errorf("sbcore exited during startup: %s", p.Result())
		}
		if _, err = p.api.Status(); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Stop()
	return fmt.Errorf("sbcore API did not come up: %w", err)
}

func (p *Process) pipeLog(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		p.mu.Lock()
		p.lastLine = line
		p.mu.Unlock()
		switch {
		case strings.Contains(line, "[Error]") || strings.Contains(line, "ERROR"):
			logger.Error("SBCORE: " + line)
		case strings.Contains(line, "[Warning]") || strings.Contains(line, "WARN"):
			logger.Warning("SBCORE: " + line)
		case strings.Contains(line, "[Debug]") || strings.Contains(line, "DEBUG"):
			logger.Debug("SBCORE: " + line)
		default:
			logger.Info("SBCORE: " + line)
		}
	}
}

func (p *Process) Stop() error {
	if !p.IsRunning() {
		return nil
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
	}
	return nil
}
