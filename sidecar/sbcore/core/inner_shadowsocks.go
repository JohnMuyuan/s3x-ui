package core

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	N "github.com/sagernet/sing/common/network"
)

// Shadowsocks is registered only as ShadowTLS's loopback inner inbound.
// sing-box's Shadowsocks inbound rebuilds connection metadata from scratch,
// dropping the user and inbound ShadowTLS authenticated, so the wrapper
// carries them through the context to the session tracker.

type detourOrigin struct {
	inbound string
	user    string
}

type detourOriginKey struct{}

type innerShadowsocks struct {
	adapter.TCPInjectableInbound
}

func registerInnerShadowsocks(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocks, newInnerShadowsocks)
}

func newInnerShadowsocks(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
	in, err := shadowsocks.NewInbound(ctx, router, logger, tag, options)
	if err != nil {
		return nil, err
	}
	injectable, ok := in.(adapter.TCPInjectableInbound)
	if !ok {
		return in, nil
	}
	return &innerShadowsocks{injectable}, nil
}

// NewConnection receives connections detoured from the ShadowTLS front, whose
// tag the router has moved to LastInbound.
func (i *innerShadowsocks) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.User != "" {
		ctx = context.WithValue(ctx, detourOriginKey{}, detourOrigin{inbound: metadata.LastInbound, user: metadata.User})
	}
	i.TCPInjectableInbound.NewConnection(ctx, conn, metadata, onClose)
}

// withDetourOrigin restores the front inbound and user for tracking.
func withDetourOrigin(ctx context.Context, metadata adapter.InboundContext) adapter.InboundContext {
	if origin, ok := ctx.Value(detourOriginKey{}).(detourOrigin); ok {
		metadata.User = origin.user
		if origin.inbound != "" {
			metadata.Inbound = origin.inbound
		}
	}
	return metadata
}
