package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/common"
	"x-ui/util/json_util"
	"x-ui/util/link"

	"github.com/xtls/xray-core/infra/conf"
)

// An outbound subscription is a remote list of share links whose nodes become
// Xray outbounds, tagged with the subscription's prefix, to route to or pool
// in a balancer (selector "<prefix>-"). The last good list is kept, so a
// provider being down does not take the outbounds away.
const outboundSubMaxBytes = 4 << 20

var tagPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

type OutboundSubscriptionService struct{}

type OutboundSubscriptionView struct {
	model.OutboundSubscription
	Tags []string `json:"tags"`
}

func (s *OutboundSubscriptionService) List() ([]OutboundSubscriptionView, error) {
	var subs []model.OutboundSubscription
	if err := database.GetDB().Order("id").Find(&subs).Error; err != nil {
		return nil, err
	}
	views := make([]OutboundSubscriptionView, 0, len(subs))
	for _, sub := range subs {
		view := OutboundSubscriptionView{OutboundSubscription: sub}
		for _, ob := range sub.Parsed() {
			view.Tags = append(view.Tags, ob["tag"].(string))
		}
		view.Outbounds = ""
		views = append(views, view)
	}
	return views, nil
}

// Save adds or changes a subscription and fetches it.
func (s *OutboundSubscriptionService) Save(sub *model.OutboundSubscription) error {
	u, err := url.Parse(strings.TrimSpace(sub.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return common.NewError("the subscription URL must be http(s)")
	}
	sub.URL = u.String()
	sub.TagPrefix = strings.TrimSuffix(strings.TrimSpace(sub.TagPrefix), "-")
	if !tagPrefixRe.MatchString(sub.TagPrefix) {
		return common.NewError("the tag prefix may use letters, digits, '.', '_' and '-'")
	}
	if sub.UpdateInterval < 1 {
		sub.UpdateInterval = 12
	}
	db := database.GetDB()
	var clash int64
	db.Model(model.OutboundSubscription{}).Where("tag_prefix = ? AND id <> ?", sub.TagPrefix, sub.Id).Count(&clash)
	if clash > 0 {
		return common.NewError("another subscription uses the prefix ", sub.TagPrefix)
	}
	if sub.Id > 0 {
		var old model.OutboundSubscription
		if err := db.First(&old, sub.Id).Error; err != nil {
			return err
		}
		sub.Outbounds, sub.LastUpdate, sub.LastError = old.Outbounds, old.LastUpdate, old.LastError
		if old.URL != sub.URL || old.TagPrefix != sub.TagPrefix {
			sub.Outbounds = ""
		}
	}
	if err := db.Save(sub).Error; err != nil {
		return err
	}
	s.refresh(sub)
	return db.Save(sub).Error
}

func (s *OutboundSubscriptionService) Delete(id int) error {
	return database.GetDB().Delete(model.OutboundSubscription{}, id).Error
}

// Refresh fetches a subscription now; it reports whether its outbounds changed.
func (s *OutboundSubscriptionService) Refresh(id int) (bool, error) {
	var sub model.OutboundSubscription
	db := database.GetDB()
	if err := db.First(&sub, id).Error; err != nil {
		return false, err
	}
	changed := s.refresh(&sub)
	if err := db.Save(&sub).Error; err != nil {
		return false, err
	}
	if sub.LastError != "" {
		return changed, common.NewError(sub.LastError)
	}
	return changed, nil
}

// RefreshDue fetches the enabled subscriptions whose interval has passed and
// reports whether any outbounds changed.
func (s *OutboundSubscriptionService) RefreshDue() bool {
	var subs []model.OutboundSubscription
	db := database.GetDB()
	if db.Where("enable = ?", true).Find(&subs).Error != nil {
		return false
	}
	changed := false
	for i := range subs {
		sub := &subs[i]
		if time.Since(time.UnixMilli(sub.LastUpdate)) < time.Duration(sub.UpdateInterval)*time.Hour {
			continue
		}
		if s.refresh(sub) {
			changed = true
		}
		db.Save(sub)
	}
	return changed
}

func (s *OutboundSubscriptionService) refresh(sub *model.OutboundSubscription) bool {
	sub.LastUpdate = time.Now().UnixMilli()
	outbounds, err := fetchOutbounds(sub.URL, sub.TagPrefix)
	if err != nil {
		sub.LastError = err.Error()
		logger.Warningf("outbound subscription %s: %v", sub.Remark, err)
		return false
	}
	sub.LastError = ""
	raw, _ := json.Marshal(outbounds)
	if string(raw) == sub.Outbounds {
		return false
	}
	sub.Outbounds = string(raw)
	return true
}

func fetchOutbounds(rawURL, prefix string) ([]map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2rayN/7.0")
	resp, err := PanelHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %s", shortError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, outboundSubMaxBytes))
	if err != nil {
		return nil, err
	}
	parsed, _, err := link.ParseSubscriptionBody(body)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	used := map[string]bool{}
	skipped := 0
	for i, ob := range parsed {
		remark, _ := ob["tag"].(string)
		tag := link.SuggestTag(prefix, remark, i+1)
		for n := 2; used[tag]; n++ {
			tag = fmt.Sprintf("%s-%d", link.SuggestTag(prefix, remark, i+1), n)
		}
		ob["tag"] = tag
		// one node Xray refuses would stop Xray with every inbound
		if err := xrayAccepts(ob); err != nil {
			skipped++
			continue
		}
		used[tag] = true
		out = append(out, ob)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable nodes in the response (%d refused)", skipped)
	}
	return out, nil
}

func xrayAccepts(ob map[string]any) error {
	raw, err := json.Marshal([]any{ob})
	if err != nil {
		return err
	}
	raw = dropAllowInsecure(raw)
	var cfgs []conf.OutboundDetourConfig
	if err := json.Unmarshal(raw, &cfgs); err != nil {
		return err
	}
	_, err = cfgs[0].Build()
	return err
}

// appendSubscriptionOutbounds adds the enabled subscriptions' outbounds after
// the template's, leaving out any whose tag is taken.
func appendSubscriptionOutbounds(outbounds json_util.RawMessage) json_util.RawMessage {
	var subs []model.OutboundSubscription
	if database.GetDB().Where("enable = ?", true).Order("id").Find(&subs).Error != nil || len(subs) == 0 {
		return outbounds
	}
	var list []map[string]any
	if json.Unmarshal(outbounds, &list) != nil {
		return outbounds
	}
	taken := map[string]bool{}
	for _, ob := range list {
		if tag, _ := ob["tag"].(string); tag != "" {
			taken[tag] = true
		}
	}
	for _, sub := range subs {
		for _, ob := range sub.Parsed() {
			tag, _ := ob["tag"].(string)
			if taken[tag] {
				continue
			}
			taken[tag] = true
			list = append(list, ob)
		}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return outbounds
	}
	return raw
}

// SubscriptionOutboundTags are the tags the enabled subscriptions add.
func SubscriptionOutboundTags() []string {
	var subs []model.OutboundSubscription
	database.GetDB().Where("enable = ?", true).Order("id").Find(&subs)
	tags := []string{}
	for _, sub := range subs {
		for _, ob := range sub.Parsed() {
			tags = append(tags, ob["tag"].(string))
		}
	}
	return tags
}
