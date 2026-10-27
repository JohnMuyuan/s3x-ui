package job

import (
	"testing"
	"time"
)

func TestThresholdAlert(t *testing.T) {
	var a thresholdAlert
	steps := []struct {
		over bool
		want bool
	}{{false, false}, {true, true}, {true, false}, {true, false}, {false, false}, {true, true}}
	for i, s := range steps {
		if got := a.due(s.over); got != s.want {
			t.Fatalf("step %d: due(%v) = %v", i, s.over, got)
		}
	}
	a.sentAt = time.Now().Add(-31 * time.Minute)
	if !a.due(true) {
		t.Error("no repeat after half an hour over the threshold")
	}
}
