package controller

import (
	"errors"
	"strconv"

	"x-ui/database/model"
	"x-ui/web/service"

	"github.com/gin-gonic/gin"
)

type XraySettingController struct {
	XraySettingService service.XraySettingService
	SettingService     service.SettingService
	InboundService     service.InboundService
	OutboundService    service.OutboundService
	XrayService        service.XrayService
	WarpService        service.WarpService

	OutboundSubscriptionService service.OutboundSubscriptionService
}

func NewXraySettingController(g *gin.RouterGroup) *XraySettingController {
	a := &XraySettingController{}
	a.initRouter(g)
	return a
}

func (a *XraySettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/xray")

	g.POST("/", a.getXraySetting)
	g.POST("/update", a.updateSetting)
	g.POST("/outboundStatus", a.outboundStatus)
	g.POST("/outboundSubs", a.outboundSubs)
	g.POST("/outboundSub/save", a.saveOutboundSub)
	g.POST("/outboundSub/del/:id", a.delOutboundSub)
	g.POST("/outboundSub/refresh/:id", a.refreshOutboundSub)
	g.POST("/testOutbound", a.testOutbound)
	g.GET("/getXrayResult", a.getXrayResult)
	g.GET("/getDefaultJsonConfig", a.getDefaultXrayConfig)
	g.POST("/warp/:action", a.warp)
	g.GET("/getOutboundsTraffic", a.getOutboundsTraffic)
	g.POST("/resetOutboundsTraffic", a.resetOutboundsTraffic)
}

func (a *XraySettingController) getXraySetting(c *gin.Context) {
	xraySetting, err := a.SettingService.GetXrayConfigTemplate()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	inboundTags, err := a.InboundService.GetInboundTags()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	xrayResponse := "{ \"xraySetting\": " + xraySetting + ", \"inboundTags\": " + inboundTags + " }"
	jsonObj(c, xrayResponse, nil)
}

func (a *XraySettingController) outboundSubs(c *gin.Context) {
	subs, err := a.OutboundSubscriptionService.List()
	jsonObj(c, subs, err)
}

func (a *XraySettingController) saveOutboundSub(c *gin.Context) {
	sub := &model.OutboundSubscription{}
	if err := c.ShouldBind(sub); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	err := a.OutboundSubscriptionService.Save(sub)
	if err == nil {
		a.XrayService.SetToNeedRestart()
		if sub.LastError != "" {
			err = errors.New(sub.LastError)
		}
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

func (a *XraySettingController) delOutboundSub(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err == nil {
		err = a.OutboundSubscriptionService.Delete(id)
	}
	if err == nil {
		a.XrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "delete"), err)
}

func (a *XraySettingController) refreshOutboundSub(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	changed := false
	if err == nil {
		changed, err = a.OutboundSubscriptionService.Refresh(id)
	}
	if changed {
		a.XrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.outbound.subRefresh"), err)
}

func (a *XraySettingController) outboundStatus(c *gin.Context) {
	jsonObj(c, service.OutboundStatus(), nil)
}

// testOutbound tests one outbound of the running Xray; speed adds a download.
func (a *XraySettingController) testOutbound(c *gin.Context) {
	testURL, _ := a.SettingService.GetOutboundTestUrl()
	jsonObj(c, service.ProbeOutbound(c.PostForm("tag"), testURL, c.PostForm("speed") == "true"), nil)
}

func (a *XraySettingController) updateSetting(c *gin.Context) {
	xraySetting := c.PostForm("xraySetting")
	err := a.XraySettingService.SaveXraySetting(xraySetting)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

func (a *XraySettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.SettingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

func (a *XraySettingController) getXrayResult(c *gin.Context) {
	jsonObj(c, a.XrayService.GetXrayResult(), nil)
}

func (a *XraySettingController) warp(c *gin.Context) {
	action := c.Param("action")
	var resp string
	var err error
	switch action {
	case "data":
		resp, err = a.WarpService.GetWarpData()
	case "del":
		err = a.WarpService.DelWarpData()
	case "config":
		resp, err = a.WarpService.GetWarpConfig()
	case "reg":
		skey := c.PostForm("privateKey")
		pkey := c.PostForm("publicKey")
		resp, err = a.WarpService.RegWarp(skey, pkey)
	case "license":
		license := c.PostForm("license")
		resp, err = a.WarpService.SetWarpLicense(license)
	}

	jsonObj(c, resp, err)
}

func (a *XraySettingController) getOutboundsTraffic(c *gin.Context) {
	outboundsTraffic, err := a.OutboundService.GetOutboundsTraffic()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getOutboundTrafficError"), err)
		return
	}
	jsonObj(c, outboundsTraffic, nil)
}

func (a *XraySettingController) resetOutboundsTraffic(c *gin.Context) {
	tag := c.PostForm("tag")
	err := a.OutboundService.ResetOutboundTraffic(tag)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.resetOutboundTrafficError"), err)
		return
	}
	jsonObj(c, "", nil)
}
