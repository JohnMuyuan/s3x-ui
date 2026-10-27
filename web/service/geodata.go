package service

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"x-ui/config"
	"x-ui/util/common"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The geo files' categories, for writing routing rules: what geosite:xxx or
// geoip:xxx holds, and which categories a domain or address falls in.
// Decoding a whole file takes some hundred MB, so the file is kept as read,
// with an index of its categories, and a category is decoded when it is asked
// for. Only the file in use is kept, for a few minutes after its last use:
// people tend to look up several things in a row.
const geoCacheTTL = 5 * time.Minute

var geoFileRe = regexp.MustCompile(`^geo(site|ip)[A-Za-z0-9_.-]*\.dat$`)

type GeoFile struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // site or ip
	Size int64  `json:"size"`
}

type GeoCategory struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// geoEntry is one GeoSite or GeoIP message of a file, still encoded. Both
// carry the code as field 1 and the domains or CIDRs as field 2.
type geoEntry struct {
	code  string
	count int
	raw   []byte
}

type geoParsed struct {
	name    string
	site    bool
	entries []geoEntry
	modTime time.Time
}

func (e geoEntry) site() *geodata.GeoSite {
	var site geodata.GeoSite
	proto.Unmarshal(e.raw, &site)
	return &site
}

func (e geoEntry) ip() *geodata.GeoIP {
	var ip geodata.GeoIP
	proto.Unmarshal(e.raw, &ip)
	return &ip
}

// indexGeo lists the entries of a GeoSiteList or GeoIPList, whose entries are
// field 1.
func indexGeo(raw []byte) ([]geoEntry, error) {
	var entries []geoEntry
	err := eachField(raw, func(num protowire.Number, msg []byte) error {
		if num != 1 {
			return nil
		}
		e := geoEntry{raw: msg}
		err := eachField(msg, func(num protowire.Number, v []byte) error {
			switch num {
			case 1:
				e.code = strings.ToLower(string(v))
			case 2:
				e.count++
			}
			return nil
		})
		entries = append(entries, e)
		return err
	})
	return entries, err
}

// eachField calls fn with each length-delimited field of a message.
func eachField(b []byte, fn func(protowire.Number, []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if err := fn(num, v); err != nil {
			return err
		}
	}
	return nil
}

var geoCache struct {
	sync.Mutex
	parsed *geoParsed
	expiry *time.Timer
}

// dropGeoCache frees the parsed file and gives the memory back.
func dropGeoCache() {
	geoCache.Lock()
	geoCache.parsed = nil
	geoCache.Unlock()
	debug.FreeOSMemory()
}

type GeodataService struct{}

func (s *GeodataService) Files() []GeoFile {
	entries, _ := os.ReadDir(config.GetBinFolderPath())
	var files []GeoFile
	for _, e := range entries {
		m := geoFileRe.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, GeoFile{Name: e.Name(), Kind: m[1], Size: info.Size()})
	}
	return files
}

func loadGeo(name string) (*geoParsed, error) {
	m := geoFileRe.FindStringSubmatch(name)
	if m == nil {
		return nil, common.NewError("not a geo file: ", name)
	}
	path := filepath.Join(config.GetBinFolderPath(), name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	geoCache.Lock()
	defer geoCache.Unlock()
	if geoCache.expiry != nil {
		geoCache.expiry.Stop()
	}
	geoCache.expiry = time.AfterFunc(geoCacheTTL, dropGeoCache)
	if parsed := geoCache.parsed; parsed != nil && parsed.name == name && parsed.modTime.Equal(info.ModTime()) {
		return parsed, nil
	}
	// the previous file goes before this one is read
	geoCache.parsed = nil
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	entries, err := indexGeo(raw)
	if err != nil {
		return nil, common.NewError(name, " is not a geo file: ", err)
	}
	parsed := &geoParsed{name: name, site: m[1] == "site", entries: entries, modTime: info.ModTime()}
	geoCache.parsed = parsed
	return parsed, nil
}

// Categories lists a file's categories whose code contains query.
func (s *GeodataService) Categories(file, query string) ([]GeoCategory, error) {
	parsed, err := loadGeo(file)
	if err != nil {
		return nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	var out []GeoCategory
	for _, e := range parsed.entries {
		if strings.Contains(e.code, query) {
			out = append(out, GeoCategory{e.code, e.count})
		}
	}
	slices.SortFunc(out, func(a, b GeoCategory) int { return strings.Compare(a.Code, b.Code) })
	return out, nil
}

// Entries lists up to limit entries of a category, in the syntax of Xray's
// routing rules ("domain:", "full:", "keyword:", "regexp:", with @attributes).
func (s *GeodataService) Entries(file, code string, limit int) ([]string, int, error) {
	parsed, err := loadGeo(file)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	for _, e := range parsed.entries {
		if e.code != strings.ToLower(code) {
			continue
		}
		if parsed.site {
			for _, d := range e.site().Domain[:min(limit, e.count)] {
				out = append(out, domainRule(d))
			}
		} else {
			for _, c := range e.ip().Cidr[:min(limit, e.count)] {
				if prefix, ok := cidrPrefix(c); ok {
					out = append(out, prefix.String())
				}
			}
		}
		return out, e.count, nil
	}
	return nil, 0, nil
}

func domainRule(d *geodata.Domain) string {
	kind := map[geodata.Domain_Type]string{geodata.Domain_Substr: "keyword:", geodata.Domain_Regex: "regexp:",
		geodata.Domain_Domain: "domain:", geodata.Domain_Full: "full:"}[d.Type]
	rule := kind + d.Value
	for _, attr := range d.Attribute {
		rule += " @" + attr.Key
	}
	return rule
}

func cidrPrefix(c *geodata.CIDR) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(c.Ip)
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, err := addr.Unmap().Prefix(int(c.Prefix) - map[bool]int{true: 96, false: 0}[addr.Is4In6()])
	return prefix, err == nil
}

// Lookup names the categories of a file a domain or address falls in, with
// the entry that matched.
func (s *GeodataService) Lookup(file, target string) ([]string, error) {
	parsed, err := loadGeo(file)
	if err != nil {
		return nil, err
	}
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return nil, common.NewError("nothing to look up")
	}
	addr, err := netip.ParseAddr(target)
	if !parsed.site && err != nil {
		return nil, common.NewError("an IP file looks up addresses")
	}
	var out []string
	for _, e := range parsed.entries {
		if !parsed.site {
			for _, c := range e.ip().Cidr {
				if prefix, ok := cidrPrefix(c); ok && prefix.Contains(addr.Unmap()) {
					out = append(out, e.code+"  ("+prefix.String()+")")
					break
				}
			}
			continue
		}
		for _, d := range e.site().Domain {
			if domainMatches(d, target) {
				out = append(out, e.code+"  ("+domainRule(d)+")")
				break
			}
		}
	}
	return out, nil
}

func domainMatches(d *geodata.Domain, host string) bool {
	switch d.Type {
	case geodata.Domain_Full:
		return host == d.Value
	case geodata.Domain_Domain:
		return host == d.Value || strings.HasSuffix(host, "."+d.Value)
	case geodata.Domain_Substr:
		return strings.Contains(host, d.Value)
	case geodata.Domain_Regex:
		re, err := regexp.Compile(d.Value)
		return err == nil && re.MatchString(host)
	}
	return false
}
