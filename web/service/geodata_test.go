package service

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestGeodata(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	sites, _ := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "GOOGLE", Domain: []*geodata.Domain{
			{Type: geodata.Domain_Domain, Value: "google.com"},
			{Type: geodata.Domain_Full, Value: "dl.google.cn", Attribute: []*geodata.Domain_Attribute{{Key: "cn"}}},
		}},
		{Code: "CATEGORY-ADS", Domain: []*geodata.Domain{{Type: geodata.Domain_Substr, Value: "adserv"}, {Type: geodata.Domain_Regex, Value: `^ad\d+\.`}}},
	}})
	v4 := netip.MustParseAddr("8.8.8.0").AsSlice()
	mapped := netip.MustParseAddr("::ffff:1.1.1.0").AsSlice()
	ips, _ := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "US", Cidr: []*geodata.CIDR{{Ip: v4, Prefix: 24}, {Ip: mapped, Prefix: 120}}},
	}})
	os.WriteFile(filepath.Join(dir, "geosite.dat"), sites, 0o644)
	os.WriteFile(filepath.Join(dir, "geoip.dat"), ips, 0o644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644)

	var s GeodataService
	if files := s.Files(); len(files) != 2 {
		t.Fatalf("files: %+v", files)
	}
	cats, err := s.Categories("geosite.dat", "goo")
	if err != nil || len(cats) != 1 || cats[0] != (GeoCategory{"google", 2}) {
		t.Errorf("categories: %+v %v", cats, err)
	}
	entries, total, _ := s.Entries("geosite.dat", "google", 10)
	if total != 2 || !slices.Equal(entries, []string{"domain:google.com", "full:dl.google.cn @cn"}) {
		t.Errorf("entries: %v %d", entries, total)
	}
	if entries, _, _ := s.Entries("geoip.dat", "us", 10); !slices.Equal(entries, []string{"8.8.8.0/24", "1.1.1.0/24"}) {
		t.Errorf("ip entries: %v", entries)
	}
	for target, want := range map[string]int{"mail.google.com": 1, "google.com.evil": 0, "x.adserver.net": 1, "ad12.example": 1} {
		if got, _ := s.Lookup("geosite.dat", target); len(got) != want {
			t.Errorf("lookup %s: %v", target, got)
		}
	}
	if got, _ := s.Lookup("geoip.dat", "1.1.1.1"); len(got) != 1 {
		t.Errorf("lookup 1.1.1.1: %v", got)
	}
	if _, err := s.Categories("../x-ui.db", ""); err == nil {
		t.Error("a path outside the geo files was read")
	}
}
