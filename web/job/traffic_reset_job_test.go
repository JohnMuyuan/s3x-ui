package job

import (
	"testing"
	"time"
)

func TestPeriodStart(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 10, 28, 15, 42, 7, 0, loc) // a Wednesday
	tests := []struct {
		period string
		day    int
		now    time.Time
		want   time.Time
	}{
		{"hourly", 0, now, time.Date(2026, 10, 28, 15, 0, 0, 0, loc)},
		{"daily", 0, now, time.Date(2026, 10, 28, 0, 0, 0, 0, loc)},
		{"weekly", 0, now, time.Date(2026, 10, 26, 0, 0, 0, 0, loc)},
		{"weekly", 0, time.Date(2026, 11, 1, 23, 0, 0, 0, loc), time.Date(2026, 10, 26, 0, 0, 0, 0, loc)}, // Sunday
		{"monthly", 15, now, time.Date(2026, 10, 15, 0, 0, 0, 0, loc)},
		{"monthly", 30, now, time.Date(2026, 9, 30, 0, 0, 0, 0, loc)},
		{"monthly", 31, time.Date(2026, 3, 2, 0, 0, 0, 0, loc), time.Date(2026, 2, 28, 0, 0, 0, 0, loc)},
		{"monthly", 31, time.Date(2027, 1, 5, 0, 0, 0, 0, loc), time.Date(2026, 12, 31, 0, 0, 0, 0, loc)},
	}
	for _, tt := range tests {
		got, ok := periodStart(tt.period, tt.day, tt.now)
		if !ok || !got.Equal(tt.want) {
			t.Errorf("%s day %d at %v: got %v, want %v", tt.period, tt.day, tt.now, got, tt.want)
		}
	}
	if _, ok := periodStart("never", 1, now); ok {
		t.Error("never has no period")
	}
}
