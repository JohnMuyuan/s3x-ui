package xray

import (
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var tunRuleRe = regexp.MustCompile(`^(\d+):.*\blookup (\d+)\b`)

// clearStaleTunRules removes the IPv6 policy rules a WireGuard outbound on a
// kernel TUN leaves behind. Xray puts them on routing tables from 10230 on
// and does not remove them when it exits, so each start would add two more.
// It is called while no Xray runs, so every such rule is a leftover.
func clearStaleTunRules() {
	if runtime.GOOS != "linux" {
		return
	}
	out, err := exec.Command("ip", "-6", "rule", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		m := tunRuleRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if table, _ := strconv.Atoi(m[2]); table < 10230 || table >= 10230+1024 {
			continue
		}
		exec.Command("ip", "-6", "rule", "del", "pref", m[1]).Run()
	}
}
