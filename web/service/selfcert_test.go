package service

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestGetSelfSignedCert(t *testing.T) {
	t.Setenv("XUI_DB_FOLDER", t.TempDir())
	var s ServerService

	first, err := s.GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := first["certFile"].(string), first["keyFile"].(string)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}
	if err = pair.Leaf.VerifyHostname(SelfSignedServerName); err != nil {
		t.Fatalf("certificate is not valid for %s: %v", SelfSignedServerName, err)
	}
	if st, _ := os.Stat(keyFile); st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}

	second, err := s.GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if first["sha256"] != second["sha256"] {
		t.Fatal("certificate was regenerated although it exists")
	}

	// A damaged certificate is replaced rather than handed out.
	if err = os.WriteFile(certFile, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := s.GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if third["sha256"] == first["sha256"] {
		t.Fatal("damaged certificate was not regenerated")
	}
	if _, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("regenerated pair does not load: %v", err)
	}
}
