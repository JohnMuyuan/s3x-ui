package sub

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/web/service"

	"github.com/goccy/go-json"
)

// A remote subscription is fetched at most every subscriptionTTL; when a fetch
// fails, the last good copy is served instead, so a provider being down for a
// while does not empty the client's subscription.
const (
	subscriptionTTL      = 5 * time.Minute
	subscriptionTimeout  = 8 * time.Second
	subscriptionMaxBytes = 2 << 20
)

var subscriptionCache = struct {
	sync.Mutex
	links map[string][]string
	at    map[string]time.Time
}{links: map[string][]string{}, at: map[string]time.Time{}}

// externalLinks renders clients' external entries: share links as they are
// (renamed by their remark), subscriptions' links merged in (prefixed by
// theirs). A link that several entries produce is listed once.
func externalLinks(entries []model.ClientExternalLink) []string {
	var out []string
	seen := map[string]bool{}
	add := func(link string) {
		if link != "" && !seen[link] {
			seen[link] = true
			out = append(out, link)
		}
	}
	for _, e := range entries {
		value := strings.TrimSpace(e.Value)
		switch e.Kind {
		case "sub":
			for _, link := range fetchSubscription(value) {
				if e.Remark != "" {
					link = renameLink(link, e.Remark+" "+linkName(link))
				}
				add(link)
			}
		default:
			if !strings.Contains(value, "://") {
				continue
			}
			if e.Remark != "" {
				value = renameLink(value, e.Remark)
			}
			add(value)
		}
	}
	return out
}

func fetchSubscription(rawURL string) []string {
	if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	subscriptionCache.Lock()
	links, at := subscriptionCache.links[rawURL], subscriptionCache.at[rawURL]
	subscriptionCache.Unlock()
	if time.Since(at) < subscriptionTTL {
		return links
	}

	fresh, err := downloadSubscription(rawURL)
	subscriptionCache.Lock()
	defer subscriptionCache.Unlock()
	if err != nil {
		logger.Warningf("external subscription %s: %v", redactURL(rawURL), err)
		// try again next time, but keep serving what was there
		return links
	}
	subscriptionCache.links[rawURL] = fresh
	subscriptionCache.at[rawURL] = time.Now()
	return fresh
}

func downloadSubscription(rawURL string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// providers send a plain share-link list to v2rayN, and Clash YAML to others
	req.Header.Set("User-Agent", "v2rayN/7.0")
	resp, err := service.PanelHTTPClient(subscriptionTimeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subscriptionMaxBytes))
	if err != nil {
		return nil, err
	}
	links := decodeLinkList(body)
	if len(links) == 0 {
		return nil, fmt.Errorf("no share links in the response")
	}
	return links, nil
}

// decodeLinkList reads a subscription body, base64 encoded or not, one share
// link per line.
func decodeLinkList(body []byte) []string {
	text := string(bytes.TrimSpace(body))
	if !strings.Contains(text, "://") {
		compact := strings.Join(strings.Fields(text), "")
		if decoded, ok := decodeBase64(compact); ok {
			text = string(decoded)
		}
	}
	var links []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); strings.Contains(line, "://") {
			links = append(links, line)
		}
	}
	return links
}

func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// linkName is a share link's node name: a vmess link's ps, otherwise its
// fragment.
func linkName(link string) string {
	if payload, ok := strings.CutPrefix(link, "vmess://"); ok {
		var node map[string]any
		if raw, ok := decodeBase64(payload); ok && json.Unmarshal(raw, &node) == nil {
			name, _ := node["ps"].(string)
			return name
		}
		return ""
	}
	_, fragment, found := strings.Cut(link, "#")
	if !found {
		return ""
	}
	if name, err := url.PathUnescape(fragment); err == nil {
		return name
	}
	return fragment
}

// renameLink gives a share link a new node name. An ssr link keeps its own:
// its name sits inside the encoded payload.
func renameLink(link, name string) string {
	name = strings.TrimSpace(name)
	if payload, ok := strings.CutPrefix(link, "vmess://"); ok {
		var node map[string]any
		raw, ok := decodeBase64(payload)
		if !ok || json.Unmarshal(raw, &node) != nil {
			return link
		}
		node["ps"] = name
		out, err := json.Marshal(node)
		if err != nil {
			return link
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(out)
	}
	if strings.HasPrefix(link, "ssr://") {
		return link
	}
	base, _, _ := strings.Cut(link, "#")
	return base + "#" + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

// redactURL keeps a subscription's token out of the log.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(invalid URL)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}
