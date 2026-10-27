package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// API is the panel-side client of sbcore's loopback management API.
type API struct {
	base   string
	token  string
	client *http.Client
}

type Stat struct {
	Resource  string `json:"resource"`
	Tag       string `json:"tag"`
	Direction bool   `json:"direction"`
	Traffic   int64  `json:"traffic"`
}

type Session struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	Source  string `json:"source"`
}

func NewAPI(addr, token string) *API {
	return &API{base: "http://" + addr, token: token, client: &http.Client{Timeout: 15 * time.Second}}
}

func (a *API) call(method, path string, body []byte, out any) error {
	req, err := http.NewRequest(method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var msg struct {
		Success bool            `json:"success"`
		Msg     string          `json:"msg"`
		Obj     json.RawMessage `json:"obj"`
	}
	if err = json.Unmarshal(raw, &msg); err != nil {
		return fmt.Errorf("sbcore %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if !msg.Success {
		return errors.New(msg.Msg)
	}
	if out != nil && len(msg.Obj) > 0 {
		return json.Unmarshal(msg.Obj, out)
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (a *API) Status() (bool, error) {
	var st struct {
		Running bool `json:"running"`
	}
	err := a.call(http.MethodGet, "/status", nil, &st)
	return st.Running, err
}

func (a *API) Start(config []byte) error {
	return a.call(http.MethodPost, "/start", config, nil)
}

func (a *API) StopCore() error {
	return a.call(http.MethodPost, "/stop", nil, nil)
}

func (a *API) AddInbound(inbound []byte) error {
	return a.call(http.MethodPost, "/inbound/add", inbound, nil)
}

func (a *API) DelInbound(tag string) error {
	return a.call(http.MethodPost, "/inbound/del", mustJSON(map[string]string{"tag": tag}), nil)
}

// UpdateUsers reports hot=false when the protocol cannot swap users in place.
func (a *API) UpdateUsers(inbound []byte) (bool, error) {
	var res struct {
		Hot bool `json:"hot"`
	}
	err := a.call(http.MethodPost, "/inbound/users", inbound, &res)
	return res.Hot, err
}

// Stats drains sbcore's counters; the caller owns the returned traffic.
func (a *API) Stats() ([]Stat, error) {
	var stats []Stat
	err := a.call(http.MethodPost, "/stats", nil, &stats)
	return stats, err
}

func (a *API) Sessions() ([]Session, error) {
	var sessions []Session
	err := a.call(http.MethodGet, "/sessions", nil, &sessions)
	return sessions, err
}

func (a *API) Kick(user string) error {
	return a.call(http.MethodPost, "/kick", mustJSON(map[string]string{"user": user}), nil)
}
