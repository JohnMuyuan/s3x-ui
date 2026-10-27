package controller

import (
	"net/http"
	"strings"

	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type APIController struct {
	BaseController
	inboundController *InboundController
	Tgbot             service.Tgbot
	apiTokenService   service.ApiTokenService
	userService       service.UserService
}

// readOnlyRoutes are what a read-only token may call, relative to
// /panel/api/inbounds.
var readOnlyRoutes = map[string]bool{
	"/list":                      true,
	"/get/:id":                   true,
	"/getClientTraffics/:email":  true,
	"/getClientTrafficsById/:id": true,
	"/clientIps/:email":          true,
	"/onlines":                   true,
}

func NewAPIController(g *gin.RouterGroup) *APIController {
	a := &APIController{}
	a.initRouter(g)
	return a
}

func (a *APIController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/panel/api/inbounds")
	g.Use(a.checkAPIAuth)

	a.inboundController = NewInboundController(g)

	inboundRoutes := []struct {
		Method  string
		Path    string
		Handler gin.HandlerFunc
	}{
		{"GET", "/createbackup", a.createBackup},
		{"GET", "/list", a.inboundController.getInbounds},
		{"GET", "/get/:id", a.inboundController.getInbound},
		{"GET", "/getClientTraffics/:email", a.inboundController.getClientTraffics},
		{"GET", "/getClientTrafficsById/:id", a.inboundController.getClientTrafficsById},
		{"POST", "/add", a.inboundController.addInbound},
		{"POST", "/del/:id", a.inboundController.delInbound},
		{"POST", "/update/:id", a.inboundController.updateInbound},
		{"POST", "/clientIps/:email", a.inboundController.getClientIps},
		{"POST", "/clearClientIps/:email", a.inboundController.clearClientIps},
		{"POST", "/addClient", a.inboundController.addInboundClient},
		{"POST", "/:id/delClient/:clientId", a.inboundController.delInboundClient},
		{"POST", "/updateClient/:clientId", a.inboundController.updateInboundClient},
		{"POST", "/:id/resetClientTraffic/:email", a.inboundController.resetClientTraffic},
		{"POST", "/resetAllTraffics", a.inboundController.resetAllTraffics},
		{"POST", "/resetAllClientTraffics/:id", a.inboundController.resetAllClientTraffics},
		{"POST", "/delDepletedClients/:id", a.inboundController.delDepletedClients},
		{"POST", "/onlines", a.inboundController.onlines},
	}

	for _, route := range inboundRoutes {
		g.Handle(route.Method, route.Path, route.Handler)
	}
}

// checkAPIAuth lets in a request with a valid API token, as the panel's
// user; without one, the login session decides.
func (a *APIController) checkAPIAuth(c *gin.Context) {
	token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	if !ok {
		a.checkLogin(c)
		return
	}
	row, ok := a.apiTokenService.Match(strings.TrimSpace(token))
	if !ok {
		pureJsonMsg(c, http.StatusUnauthorized, false, "invalid, disabled or expired API token")
		c.Abort()
		return
	}
	_, route, _ := strings.Cut(c.FullPath(), "/panel/api/inbounds")
	if row.Scope != service.ApiScopeFull && !readOnlyRoutes[route] {
		pureJsonMsg(c, http.StatusForbidden, false, "this API token is read-only")
		c.Abort()
		return
	}
	user, err := a.userService.GetFirstUser()
	if err != nil {
		pureJsonMsg(c, http.StatusInternalServerError, false, err.Error())
		c.Abort()
		return
	}
	session.SetAPIUser(c, user)
	c.Next()
}

func (a *APIController) createBackup(c *gin.Context) {
	a.Tgbot.SendBackupToAdmins()
}
