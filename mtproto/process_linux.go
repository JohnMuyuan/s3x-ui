package mtproto

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killStray kills processes running our mtg binary, by executable or argv[0]
// name so one whose binary an update replaced is still found.
func killStray(name string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		argv0, _, _ := strings.Cut(string(cmdline), "\x00")
		if strings.TrimSuffix(filepath.Base(exe), " (deleted)") != name && filepath.Base(argv0) != name {
			continue
		}
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			killed++
		}
	}
	return killed
}
