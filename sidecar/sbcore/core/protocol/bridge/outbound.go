// Package bridge is sbcore's way back into Xray: a SOCKS5 outbound that logs
// in as the tag of the inbound each connection came from, so the panel's Xray
// routing can tell the sing-box inbounds apart (Xray takes a SOCKS username
// as the user's email, which a routing rule's "user" matches).
package bridge

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const Type = "xray-bridge"

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SOCKSOutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger   log.ContextLogger
	dialer   N.Dialer
	server   M.Socksaddr
	username string
	password string

	mu      sync.Mutex
	clients map[string]*socks.Client
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:  outbound.NewAdapterWithDialerOptions(Type, tag, options.Network.Build(), options.DialerOptions),
		logger:   logger,
		dialer:   outboundDialer,
		server:   options.ServerOptions.Build(),
		username: options.Username,
		password: options.Password,
		clients:  map[string]*socks.Client{},
	}, nil
}

// client logs in as the connection's inbound, or as the configured user when
// the connection has none.
func (h *Outbound) client(ctx context.Context) *socks.Client {
	user := h.username
	if metadata := adapter.ContextFrom(ctx); metadata != nil && metadata.Inbound != "" {
		user = metadata.Inbound
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.clients[user]
	if !ok {
		c = socks.NewClient(h.dialer, h.server, socks.Version5, user, h.password)
		h.clients[user] = c
	}
	return c
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c := h.client(ctx)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	return c.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	c := h.client(ctx)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return c.ListenPacket(ctx, destination)
}
