//go:build !linux

package mtproto

func killStray(string) int { return 0 }
