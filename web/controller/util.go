package controller

import (
	"net"
	"net/http"

	"x-ui/config"
	"x-ui/logger"
	"x-ui/web/entity"
	"x-ui/web/service"

	"github.com/gin-gonic/gin"
)

// getRemoteIp is the client's address; forwarding headers count only from a
// trusted proxy (trustedProxyCIDRs).
func getRemoteIp(c *gin.Context) string {
	var settings service.SettingService
	return settings.ClientIP(c.Request.RemoteAddr, c.GetHeader("X-Real-IP"), c.GetHeader("X-Forwarded-For"))
}

func jsonMsg(c *gin.Context, msg string, err error) {
	jsonMsgObj(c, msg, nil, err)
}

func jsonObj(c *gin.Context, obj any, err error) {
	jsonMsgObj(c, "", obj, err)
}

func jsonMsgObj(c *gin.Context, msg string, obj any, err error) {
	m := entity.Msg{
		Obj: obj,
	}
	if err == nil {
		m.Success = true
		if msg != "" {
			m.Msg = msg
		}
	} else {
		m.Success = false
		m.Msg = msg + " (" + err.Error() + ")"
		logger.Warning(msg+" "+I18nWeb(c, "fail")+": ", err)
	}
	c.JSON(http.StatusOK, m)
}

func pureJsonMsg(c *gin.Context, statusCode int, success bool, msg string) {
	c.JSON(statusCode, entity.Msg{
		Success: success,
		Msg:     msg,
	})
}

func html(c *gin.Context, name string, title string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data["title"] = title
	host := ""
	var settings service.SettingService
	if settings.ViaTrustedProxy(c.Request.RemoteAddr) {
		host = c.GetHeader("X-Forwarded-Host")
		if host == "" {
			host = c.GetHeader("X-Real-IP")
		}
	}
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(c.Request.Host)
		if err != nil {
			host = c.Request.Host
		}
	}
	data["host"] = host
	data["request_uri"] = c.Request.RequestURI
	data["base_path"] = c.GetString("base_path")
	c.HTML(http.StatusOK, name, getContext(data))
}

// AssetsVersion tags asset URLs. Assets are cached for a year and the display
// version stays at the 2.6.2 base, so the tag must follow the asset content.
var AssetsVersion = config.GetVersion()

func getContext(h gin.H) gin.H {
	a := gin.H{
		"cur_ver":   config.GetVersion(),
		"asset_ver": AssetsVersion,
	}
	for key, value := range h {
		a[key] = value
	}
	return a
}

func isAjax(c *gin.Context) bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}
