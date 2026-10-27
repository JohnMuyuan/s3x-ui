package sub

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"x-ui/database/model"

	"github.com/goccy/go-json"
)

func TestRenameLink(t *testing.T) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"old","add":"a.example","port":"443","id":"x"}`))
	renamed := renameLink(vmess, "HK 01")
	if linkName(renamed) != "HK 01" {
		t.Errorf("vmess rename: %q", linkName(renamed))
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(renamed, "vmess://"))
	var node map[string]any
	json.Unmarshal(raw, &node)
	if node["add"] != "a.example" {
		t.Errorf("vmess rename lost fields: %s", raw)
	}
	cases := map[string]string{
		"vless://id@h:443?security=reality#old%20name": "vless://id@h:443?security=reality#HK%2001",
		"hysteria2://pw@h:443/?sni=x":                  "hysteria2://pw@h:443/?sni=x#HK%2001",
		"ssr://abcdef":                                 "ssr://abcdef",
	}
	for in, want := range cases {
		if got := renameLink(in, "HK 01"); got != want {
			t.Errorf("renameLink(%q) = %q, want %q", in, got, want)
		}
	}
	if linkName("trojan://pw@h:443#%E9%A6%99%E6%B8%AF") != "香港" {
		t.Error("linkName does not unescape")
	}
}

func TestDecodeLinkList(t *testing.T) {
	list := "vless://a@h:1#one\r\ntrojan://b@h:2#two\n\nnot a link\n"
	for _, body := range []string{list, base64.StdEncoding.EncodeToString([]byte(list)),
		base64.RawURLEncoding.EncodeToString([]byte(list)), wrap(base64.StdEncoding.EncodeToString([]byte(list)))} {
		if got := decodeLinkList([]byte(body)); !slices.Equal(got, []string{"vless://a@h:1#one", "trojan://b@h:2#two"}) {
			t.Errorf("decodeLinkList(%q) = %q", body, got)
		}
	}
	if got := decodeLinkList([]byte("proxies:\n  - name: x\n")); len(got) != 0 {
		t.Errorf("Clash YAML read as links: %q", got)
	}
}

// wrap breaks base64 into 76-column lines, as some providers send it
func wrap(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\n")
		s = s[76:]
	}
	return b.String() + s
}

func TestExternalLinks(t *testing.T) {
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("vless://a@h:1#JP\ntrojan://b@h:2#US"))))
	}))
	defer srv.Close()
	entries := []model.ClientExternalLink{
		{Kind: "link", Value: "hysteria2://pw@h:443#x", Remark: "Home"},
		{Kind: "sub", Value: srv.URL + "/sub?token=secret", Remark: "Air"},
		{Kind: "link", Value: "hysteria2://pw@h:443#x", Remark: "Home"},
		{Kind: "link", Value: "garbage"},
	}
	want := []string{"hysteria2://pw@h:443#Home", "vless://a@h:1#Air%20JP", "trojan://b@h:2#Air%20US"}
	if got := externalLinks(entries); !slices.Equal(got, want) {
		t.Errorf("externalLinks = %q, want %q", got, want)
	}
	// the provider going down keeps the last copy
	up = false
	subscriptionCache.Lock()
	for k := range subscriptionCache.at {
		subscriptionCache.at[k] = subscriptionCache.at[k].Add(-subscriptionTTL)
	}
	subscriptionCache.Unlock()
	if got := externalLinks(entries); !slices.Equal(got, want) {
		t.Errorf("after a failed refetch = %q, want %q", got, want)
	}
	if redactURL(srv.URL+"/sub?token=secret") != srv.URL+"/…" {
		t.Errorf("redactURL leaks: %s", redactURL(srv.URL+"/sub?token=secret"))
	}
}
