package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/util/common"
)

// API tokens let scripts call /panel/api with "Authorization: Bearer <token>"
// instead of logging in. Only a token's SHA-256 is stored: the token itself
// is shown once, when it is made.
const (
	ApiScopeFull     = "full"
	ApiScopeReadOnly = "readonly"
)

type ApiTokenService struct{}

func hashApiToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *ApiTokenService) List() ([]model.ApiToken, error) {
	var tokens []model.ApiToken
	err := database.GetDB().Order("id").Find(&tokens).Error
	for i := range tokens {
		tokens[i].Hash = ""
	}
	return tokens, err
}

// Create makes a token; days > 0 makes it expire after that many days.
func (s *ApiTokenService) Create(name, scope string, days int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", common.NewError("a token needs a name of up to 64 characters")
	}
	if scope != ApiScopeFull && scope != ApiScopeReadOnly {
		return "", common.NewError("unknown scope ", scope)
	}
	db := database.GetDB()
	var taken int64
	db.Model(model.ApiToken{}).Where("name = ?", name).Count(&taken)
	if taken > 0 {
		return "", common.NewError("a token named ", name, " exists")
	}
	token := "s3x_" + rand.Text()
	row := &model.ApiToken{Name: name, Hash: hashApiToken(token), Scope: scope, Enabled: true, CreatedAt: time.Now().Unix()}
	if days > 0 {
		row.ExpiresAt = time.Now().AddDate(0, 0, days).Unix()
	}
	return token, db.Create(row).Error
}

func (s *ApiTokenService) SetEnabled(id int, enabled bool) error {
	return database.GetDB().Model(model.ApiToken{}).Where("id = ?", id).Update("enabled", enabled).Error
}

func (s *ApiTokenService) Delete(id int) error {
	return database.GetDB().Delete(model.ApiToken{}, id).Error
}

// Match finds the enabled, unexpired token a request presents, and notes its
// use (at most once a minute).
func (s *ApiTokenService) Match(token string) (*model.ApiToken, bool) {
	if !strings.HasPrefix(token, "s3x_") {
		return nil, false
	}
	db := database.GetDB()
	var row model.ApiToken
	if db.Where("hash = ?", hashApiToken(token)).First(&row).Error != nil || !row.Enabled {
		return nil, false
	}
	now := time.Now().Unix()
	if row.ExpiresAt > 0 && now >= row.ExpiresAt {
		return nil, false
	}
	if now-row.LastUsedAt >= 60 {
		db.Model(model.ApiToken{}).Where("id = ?", row.Id).Update("last_used_at", now)
	}
	return &row, true
}
