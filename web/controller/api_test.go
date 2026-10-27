package controller

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestCheckAPIAuth(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Skip("no database:", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := database.GetDB().DB(); err == nil {
			sqlDB.Close()
		}
	})
	var tokens service.ApiTokenService
	full, err := tokens.Create("full", service.ApiScopeFull, 0)
	if err != nil {
		t.Fatal(err)
	}
	readonly, _ := tokens.Create("ro", service.ApiScopeReadOnly, 1)
	off, _ := tokens.Create("off", service.ApiScopeFull, 0)
	expired, _ := tokens.Create("expired", service.ApiScopeFull, 0)
	if _, err := tokens.Create("full", service.ApiScopeFull, 0); err == nil {
		t.Error("a second token named full was made")
	}
	db := database.GetDB()
	db.Model(model.ApiToken{}).Where("name = ?", "off").Update("enabled", false)
	db.Model(model.ApiToken{}).Where("name = ?", "expired").Update("expires_at", 1)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions("s", cookie.NewStore([]byte("test"))))
	g := r.Group("/panel/api/inbounds")
	a := &APIController{}
	g.Use(a.checkAPIAuth)
	ok := func(c *gin.Context) { c.String(http.StatusOK, session.GetLoginUser(c).Username) }
	g.GET("/list", ok)
	g.POST("/add", ok)

	for _, tc := range []struct {
		token, method, path string
		code                int
	}{
		{full, "GET", "/list", 200},
		{full, "POST", "/add", 200},
		{readonly, "GET", "/list", 200},
		{readonly, "POST", "/add", 403},
		{off, "GET", "/list", 401},
		{expired, "GET", "/list", 401},
		{"s3x_wrong", "GET", "/list", 401},
		{"", "GET", "/list", 401},
	} {
		req := httptest.NewRequest(tc.method, "/panel/api/inbounds"+tc.path, nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Errorf("%q %s %s: %d, want %d", tc.token, tc.method, tc.path, w.Code, tc.code)
		}
		if w.Code == 200 && w.Body.String() != "admin" {
			t.Errorf("logged in as %q", w.Body.String())
		}
	}
	list, _ := tokens.List()
	for _, row := range list {
		if row.Hash != "" {
			t.Error("List shows a hash")
		}
		if (row.Name == "full" || row.Name == "ro") && row.LastUsedAt == 0 {
			t.Errorf("%s has no last use", row.Name)
		}
	}
}
