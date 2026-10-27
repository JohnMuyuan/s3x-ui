package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core"
)

const maxBody = 32 << 20

type api struct {
	core  *core.Core
	token string
	// lifecycle serialises start/stop against inbound mutations, so an add
	// never lands on a box that a concurrent restart is about to replace.
	lifecycle sync.Mutex
}

type userRef struct {
	Tag  string `json:"tag"`
	User string `json:"user"`
}

func newAPI(c *core.Core, token string) http.Handler {
	a := &api{core: c, token: token}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", a.status)
	mux.HandleFunc("POST /start", a.start)
	mux.HandleFunc("POST /stop", a.stop)
	mux.HandleFunc("POST /inbound/add", a.addInbound)
	mux.HandleFunc("POST /inbound/del", a.delInbound)
	mux.HandleFunc("POST /inbound/users", a.updateUsers)
	mux.HandleFunc("POST /stats", a.stats)
	mux.HandleFunc("GET /sessions", a.sessions)
	mux.HandleFunc("POST /kick", a.kick)
	return a.auth(mux)
}

func (a *api) auth(next http.Handler) http.Handler {
	want := []byte("Bearer " + a.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, obj any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": obj})
}

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxBody))
}

func (a *api) status(w http.ResponseWriter, _ *http.Request) {
	reply(w, map[string]any{"running": a.core.IsRunning()}, nil)
}

// start replaces whatever is running with the posted full sing-box config.
func (a *api) start(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		reply(w, nil, err)
		return
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	if err = a.core.Stop(); err == nil {
		err = a.core.Start(body)
	}
	reply(w, nil, err)
}

func (a *api) stop(w http.ResponseWriter, _ *http.Request) {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	reply(w, nil, a.core.Stop())
}

func (a *api) addInbound(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		reply(w, nil, err)
		return
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	reply(w, nil, a.core.AddInbound(body))
}

func (a *api) delInbound(w http.ResponseWriter, r *http.Request) {
	var ref userRef
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&ref); err != nil {
		reply(w, nil, err)
		return
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	err := a.core.RemoveInbound(ref.Tag)
	if box := a.core.GetInstance(); box != nil {
		box.SessionTracker().CloseByInbound(ref.Tag)
	}
	reply(w, nil, err)
}

// updateUsers swaps an inbound's user list in place. hot=false means the
// protocol cannot do that and the caller must re-add the inbound instead.
func (a *api) updateUsers(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		reply(w, nil, err)
		return
	}
	var head struct {
		Tag   string `json:"tag"`
		Users []struct {
			Name string `json:"name"`
		} `json:"users"`
	}
	if err = json.Unmarshal(body, &head); err != nil {
		reply(w, nil, err)
		return
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	hot, err := a.core.UpdateInboundUsers(body)
	if err == nil && hot {
		keep := make(map[string]struct{}, len(head.Users))
		for _, u := range head.Users {
			keep[u.Name] = struct{}{}
		}
		a.core.CloseInboundUserSessions(head.Tag, keep)
		if box := a.core.GetInstance(); box != nil {
			box.SessionTracker().CloseByInboundUsers(head.Tag, keep)
		}
	}
	reply(w, map[string]bool{"hot": hot}, err)
}

// stats drains the traffic counters; the caller owns what it receives.
func (a *api) stats(w http.ResponseWriter, _ *http.Request) {
	box := a.core.GetInstance()
	if box == nil {
		reply(w, []core.Stats{}, nil)
		return
	}
	reply(w, box.SessionTracker().GetStats(), nil)
}

func (a *api) sessions(w http.ResponseWriter, _ *http.Request) {
	box := a.core.GetInstance()
	if box == nil {
		reply(w, []core.SessionInfo{}, nil)
		return
	}
	reply(w, box.SessionTracker().Sessions(), nil)
}

func (a *api) kick(w http.ResponseWriter, r *http.Request) {
	var ref userRef
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&ref); err != nil {
		reply(w, nil, err)
		return
	}
	n := a.core.KickUserSessions(ref.User)
	if box := a.core.GetInstance(); box != nil {
		n += box.SessionTracker().CloseByUser(ref.User)
	}
	reply(w, map[string]int{"closed": n}, nil)
}
