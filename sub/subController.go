package sub

import (
	"encoding/base64"
	"net"
	"strings"

	"x-ui/web/service"

	"github.com/gin-gonic/gin"
)

type SUBController struct {
	subTitle       string
	subPath        string
	subJsonPath    string
	subEncrypt     bool
	updateInterval string

	subService     *SubService
	subJsonService *SubJsonService
	settingService service.SettingService
}

func NewSUBController(
	g *gin.RouterGroup,
	subPath string,
	jsonPath string,
	encrypt bool,
	showInfo bool,
	rModel string,
	update string,
	jsonFragment string,
	jsonNoise string,
	jsonMux string,
	jsonRules string,
	subTitle string,
) *SUBController {
	sub := NewSubService(showInfo, rModel)
	a := &SUBController{
		subTitle:       subTitle,
		subPath:        subPath,
		subJsonPath:    jsonPath,
		subEncrypt:     encrypt,
		updateInterval: update,

		subService:     sub,
		subJsonService: NewSubJsonService(jsonFragment, jsonNoise, jsonMux, jsonRules, sub),
	}
	a.initRouter(g)
	return a
}

func (a *SUBController) initRouter(g *gin.RouterGroup) {
	gLink := g.Group(a.subPath)
	gJson := g.Group(a.subJsonPath)

	gLink.GET(":subid", a.subs)

	gJson.GET(":subid", a.subJsons)
}

func (a *SUBController) subs(c *gin.Context) {
	subId := c.Param("subid")
	host := a.requestHost(c)
	subs, header, err := a.subService.GetSubs(subId, host)
	if err != nil || len(subs) == 0 {
		c.String(400, "Error!")
	} else {
		result := ""
		for _, sub := range subs {
			result += sub + "\n"
		}

		// Add headers
		c.Writer.Header().Set("Subscription-Userinfo", header)
		c.Writer.Header().Set("Profile-Update-Interval", a.updateInterval)
		c.Writer.Header().Set("Profile-Title", "base64:" + base64.StdEncoding.EncodeToString([]byte(a.subTitle)))

		if a.subEncrypt {
			c.String(200, base64.StdEncoding.EncodeToString([]byte(result)))
		} else {
			c.String(200, result)
		}
	}
}

func (a *SUBController) subJsons(c *gin.Context) {
	subId := c.Param("subid")
	host := a.requestHost(c)
	jsonSub, header, err := a.subJsonService.GetJson(subId, host)
	if err != nil || len(jsonSub) == 0 {
		c.String(400, "Error!")
	} else {

		// Add headers
		c.Writer.Header().Set("Subscription-Userinfo", header)
		c.Writer.Header().Set("Profile-Update-Interval", a.updateInterval)
		c.Writer.Header().Set("Profile-Title", "base64:" + base64.StdEncoding.EncodeToString([]byte(a.subTitle)))

		c.String(200, jsonSub)
	}
}

// requestHost is the host the client asked for: the forwarded host when a
// trusted proxy passed the request on, else the Host header.
func (a *SUBController) requestHost(c *gin.Context) string {
	if a.settingService.ViaTrustedProxy(c.Request.RemoteAddr) {
		if h, err := getHostFromXFH(c.GetHeader("X-Forwarded-Host")); err == nil && h != "" {
			return h
		}
		if h := c.GetHeader("X-Real-IP"); h != "" {
			return h
		}
	}
	host, _, err := net.SplitHostPort(c.Request.Host)
	if err != nil {
		host = c.Request.Host
	}
	return host
}

func getHostFromXFH(s string) (string, error) {
	if strings.Contains(s, ":") {
		realHost, _, err := net.SplitHostPort(s)
		if err != nil {
			return "", err
		}
		return realHost, nil
	}
	return s, nil
}
