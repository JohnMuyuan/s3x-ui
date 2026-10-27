package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A Reality target must look like an ordinary modern site: TLS 1.3 with
// X25519, HTTP/2, and a publicly trusted certificate for the name clients
// send. The scan handshakes with each candidate the way a browser would and
// says which qualify, fastest first.
const (
	realityProbeTimeout = 8 * time.Second
	realityCIDRTimeout  = 4 * time.Second
	realityConcurrency  = 32
	realityMaxCIDRHosts = 256
	realityMaxProbes    = 512
)

var DefaultRealityCandidates = []string{
	"www.microsoft.com", "www.apple.com", "www.amazon.com", "aws.amazon.com", "www.samsung.com",
	"www.nvidia.com", "www.amd.com", "www.intel.com", "www.sony.com", "dl.google.com",
	"www.cloudflare.com", "www.oracle.com", "www.tesla.com", "www.yahoo.com", "www.lovelive-anime.jp",
}

type RealityScanResult struct {
	Target      string   `json:"target"`
	Host        string   `json:"host"`
	IP          string   `json:"ip"`
	Feasible    bool     `json:"feasible"`
	TLSVersion  string   `json:"tlsVersion"`
	ALPN        string   `json:"alpn"`
	Curve       string   `json:"curve"`
	CertValid   bool     `json:"certValid"`
	CertIssuer  string   `json:"certIssuer"`
	ServerNames []string `json:"serverNames"`
	LatencyMs   int      `json:"latencyMs"`
	Reason      string   `json:"reason"`
}

type realityProbe struct {
	host    string // dialed: a name, or an address of a scanned range
	port    int
	sni     string // "" for an address: the certificate names it
	timeout time.Duration
	inRange bool
}

// ScanRealityTargets probes candidates: host[:port] entries and CIDR ranges
// (up to 256 addresses each, reported only where something answers TLS),
// separated by commas, spaces or new lines. None given, a default list.
func (s *ServerService) ScanRealityTargets(candidates string) []*RealityScanResult {
	tokens := strings.FieldsFunc(candidates, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	if len(tokens) == 0 {
		tokens = DefaultRealityCandidates
	}
	var probes []realityProbe
	var results []*RealityScanResult
	for _, token := range tokens {
		if strings.Contains(token, "/") {
			prefix, err := netip.ParsePrefix(token)
			if err != nil || privateAddr(prefix.Addr()) {
				results = append(results, &RealityScanResult{Target: token, Reason: "not a public CIDR range"})
				continue
			}
			for addr, n := prefix.Masked().Addr(), 0; prefix.Contains(addr) && n < realityMaxCIDRHosts; addr, n = addr.Next(), n+1 {
				probes = append(probes, realityProbe{host: addr.String(), port: 443, timeout: realityCIDRTimeout, inRange: true})
			}
			continue
		}
		host, port := token, 443
		if h, p, err := net.SplitHostPort(token); err == nil {
			host = h
			if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
				results = append(results, &RealityScanResult{Target: token, Reason: "bad port"})
				continue
			}
		}
		sni := host
		if _, err := netip.ParseAddr(host); err == nil {
			sni = ""
		}
		probes = append(probes, realityProbe{host: host, port: port, sni: sni, timeout: realityProbeTimeout})
	}
	if len(probes) > realityMaxProbes {
		probes = probes[:realityMaxProbes]
	}

	probed := make([]*RealityScanResult, len(probes))
	sem := make(chan struct{}, realityConcurrency)
	var wg sync.WaitGroup
	for i, pr := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := probeReality(pr)
			// silent addresses of a range are just not there
			if pr.inRange && r.TLSVersion == "" {
				return
			}
			probed[i] = r
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, r := range probed {
		if r != nil && !seen[r.Target] {
			seen[r.Target] = true
			results = append(results, r)
		}
	}
	slices.SortStableFunc(results, func(a, b *RealityScanResult) int {
		if a.Feasible != b.Feasible {
			if a.Feasible {
				return -1
			}
			return 1
		}
		return a.LatencyMs - b.LatencyMs
	})
	return results
}

func privateAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() ||
		addr.IsMulticast() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

func probeReality(pr realityProbe) *RealityScanResult {
	addr := net.JoinHostPort(pr.host, strconv.Itoa(pr.port))
	res := &RealityScanResult{Target: addr, Host: pr.host}
	ctx, cancel := context.WithTimeout(context.Background(), pr.timeout)
	defer cancel()

	// the panel must not become a way to look into its own network
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", pr.host)
	if err != nil || len(ips) == 0 {
		res.Reason = "does not resolve"
		return res
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Is4() {
			ip = candidate
			break
		}
	}
	res.IP = ip.Unmap().String()
	if privateAddr(ip) {
		res.Reason = "private address"
		return res
	}

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(res.IP, strconv.Itoa(pr.port)))
	if err != nil {
		res.Reason = "connection failed"
		return res
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(pr.timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         pr.sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Reason = "TLS handshake failed"
		return res
	}
	res.LatencyMs = int(time.Since(start).Milliseconds())

	st := tlsConn.ConnectionState()
	res.TLSVersion = map[uint16]string{tls.VersionTLS13: "1.3", tls.VersionTLS12: "1.2"}[st.Version]
	res.ALPN = st.NegotiatedProtocol
	res.Curve = map[tls.CurveID]string{tls.X25519: "X25519", tls.X25519MLKEM768: "X25519MLKEM768"}[st.CurveID]
	if len(st.PeerCertificates) == 0 {
		res.Reason = "no certificate"
		return res
	}
	leaf := st.PeerCertificates[0]
	if len(leaf.Issuer.Organization) > 0 {
		res.CertIssuer = leaf.Issuer.Organization[0]
	} else {
		res.CertIssuer = leaf.Issuer.CommonName
	}
	for _, name := range leaf.DNSNames {
		if !strings.HasPrefix(name, "*.") {
			res.ServerNames = append(res.ServerNames, name)
		}
	}
	name := pr.sni
	if name == "" {
		// an address of a range: offer it under the name its certificate gives
		if leaf.Subject.CommonName != "" && !strings.HasPrefix(leaf.Subject.CommonName, "*.") {
			name = leaf.Subject.CommonName
		} else if len(res.ServerNames) > 0 {
			name = res.ServerNames[0]
		}
		if name != "" {
			res.Host = name
		}
	}
	opts := x509.VerifyOptions{DNSName: name, Intermediates: x509.NewCertPool()}
	for _, cert := range st.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, verr := leaf.Verify(opts)
	res.CertValid = name != "" && verr == nil

	switch {
	case res.TLSVersion != "1.3":
		res.Reason = "no TLS 1.3"
	case res.ALPN != "h2":
		res.Reason = "no HTTP/2"
	case res.Curve == "":
		res.Reason = "no X25519 key exchange"
	case !res.CertValid:
		res.Reason = "certificate not trusted for " + name
	default:
		res.Feasible = true
	}
	return res
}
