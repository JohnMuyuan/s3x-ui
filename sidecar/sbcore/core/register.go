package core

import (
	suiAnytls "github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/anytls"
	"github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/bridge"
	suiHysteria "github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/hysteria"
	suiHysteria2 "github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/hysteria2"
	suiSnell "github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/snell"
	suiTuic "github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core/protocol/tuic"

	sbCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/naive"
	// Naive's HTTP/3 listener; without it naive panics on start.
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
)

// The sidecar only serves the protocols Xray lacks; everything else stays in Xray.
func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	suiAnytls.RegisterInbound(registry)
	suiSnell.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	// Only as ShadowTLS's loopback inner inbound; Xray serves Shadowsocks itself.
	registerInnerShadowsocks(registry)

	suiHysteria.RegisterInbound(registry)
	suiTuic.RegisterInbound(registry)
	suiHysteria2.RegisterInbound(registry)

	return registry
}

// bridge (and plain socks) carries traffic back into Xray so the panel's
// routing applies.
func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)
	socks.RegisterOutbound(registry)
	bridge.RegisterOutbound(registry)

	return registry
}

func EndpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)

	return registry
}

func ServiceRegistry() *service.Registry {
	return service.NewRegistry()
}

func CertificateProviderRegistry() *sbCertificate.Registry {
	return sbCertificate.NewRegistry()
}
