package service

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestFetchOutbounds(t *testing.T) {
	links := "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?security=tls&sni=a.example&type=tcp#JP 01\n" +
		"trojan://pw@198.51.100.8:443?sni=b.example#JP 01\n" +
		"ss://" + base64.StdEncoding.EncodeToString([]byte("rc4:pw")) + "@198.51.100.9:8388#Broken\n" +
		"hysteria2://pw@198.51.100.10:443/?sni=c.example#US"
	var agent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.UserAgent()
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer srv.Close()

	got, err := fetchOutbounds(srv.URL, "air")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, ob := range got {
		tags = append(tags, ob["tag"].(string))
	}
	if want := []string{"air-jp-01", "air-jp-01-2", "air-us"}; !slices.Equal(tags, want) {
		t.Errorf("tags = %v, want %v (the node Xray refuses left out)", tags, want)
	}
	if agent != "v2rayN/7.0" {
		t.Errorf("User-Agent %q", agent)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proxies: []"))
	}))
	defer empty.Close()
	if _, err := fetchOutbounds(empty.URL, "x"); err == nil {
		t.Error("a body without links must be an error, keeping the last good list")
	}
}
