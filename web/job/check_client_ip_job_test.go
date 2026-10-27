package job

import (
	"reflect"
	"testing"

	"x-ui/singbox"
)

func TestSingboxClientIps(t *testing.T) {
	sessions := []singbox.Session{
		{User: "a", Source: "203.0.113.9:4000", CreatedAt: 30},
		{User: "a", Source: "198.51.100.7:5000", CreatedAt: 10},
		{User: "a", Source: "203.0.113.9:4001", CreatedAt: 5}, // same IP, earlier session wins
		{User: "a", Source: "[2001:db8::1]:443", CreatedAt: 20},
		{User: "a", Source: "[::ffff:192.0.2.1]:80", CreatedAt: 40},
		{User: "a", Source: "127.0.0.1:9000", CreatedAt: 1},
		{User: "", Source: "192.0.2.50:1", CreatedAt: 1},
		{User: "b", Source: "garbage", CreatedAt: 1},
		{User: "b", Source: "192.0.2.2:1", CreatedAt: 1},
	}
	got := singboxClientIps(sessions)
	want := map[string][]string{
		"a": {"203.0.113.9", "198.51.100.7", "2001:db8::1", "192.0.2.1"},
		"b": {"192.0.2.2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
