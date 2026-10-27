package service

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"

	"x-ui/xray"
)

// VlessEncAuth is one key pair from `xray vlessenc`: the server keeps
// Decryption, clients get Encryption through the share link.
type VlessEncAuth struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Decryption string `json:"decryption"`
	Encryption string `json:"encryption"`
}

// GetNewVlessEnc generates fresh VLESS encryption keys: X25519 and the
// post-quantum ML-KEM-768, each in the native, xorpub and random modes.
func (s *ServerService) GetNewVlessEnc() ([]VlessEncAuth, error) {
	cmd := exec.Command(xray.GetBinaryPath(), "vlessenc")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	auths := parseVlessEnc(out.String())
	if len(auths) == 0 {
		return nil, errors.New("xray vlessenc printed no keys")
	}
	native := auths
	for _, a := range native {
		for _, mode := range []string{"xorpub", "random"} {
			auths = append(auths, VlessEncAuth{
				ID:         a.ID + "_" + mode,
				Label:      a.Label + " (" + mode + ")",
				Decryption: strings.Replace(a.Decryption, ".native.", "."+mode+".", 1),
				Encryption: strings.Replace(a.Encryption, ".native.", "."+mode+".", 1),
			})
		}
	}
	return auths, nil
}

// parseVlessEnc reads blocks of the form
//
//	Authentication: ML-KEM-768, Post-Quantum
//	"decryption": "mlkem768x25519plus.native.600s.<key>"
//	"encryption": "mlkem768x25519plus.native.0rtt.<key>"
func parseVlessEnc(output string) []VlessEncAuth {
	var auths []VlessEncAuth
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if label, ok := strings.CutPrefix(line, "Authentication:"); ok {
			label = strings.TrimSpace(label)
			id := "x25519"
			if strings.HasPrefix(label, "ML-KEM-768") {
				id = "mlkem768"
			}
			auths = append(auths, VlessEncAuth{ID: id, Label: label})
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || len(auths) == 0 {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `",`)
		switch strings.Trim(key, `" `) {
		case "decryption":
			auths[len(auths)-1].Decryption = val
		case "encryption":
			auths[len(auths)-1].Encryption = val
		}
	}
	complete := auths[:0]
	for _, a := range auths {
		if a.Decryption != "" && a.Encryption != "" {
			complete = append(complete, a)
		}
	}
	return complete
}
