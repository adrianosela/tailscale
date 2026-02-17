// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/rtclib"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// webrtcConnState represents the state of a WebRTC connection.
type webrtcConnState int

const (
	webrtcStateIdle webrtcConnState = iota
	webrtcStateConnecting
	webrtcStateConnected
	webrtcStateFailed
	webrtcStateClosed
)

// webrtcPeerState tracks WebRTC connection state for a single peer.
type webrtcPeerState struct {
	ep            *endpoint
	peerConn      *webrtc.PeerConnection
	dataChannel   *webrtc.DataChannel
	localDisco    key.DiscoPublic
	remoteDisco   key.DiscoPublic
	remoteNodeKey key.NodePublic // peer's node public key (for WireGuard)
	remoteAddr    netip.AddrPort // actual remote address from ICE candidate
	state         webrtcConnState
	lastError     error
	createdAt     time.Time
}

// webrtcConnectionReadyEvent signals that a WebRTC connection is ready.
type webrtcConnectionReadyEvent struct {
	remoteDisco key.DiscoPublic
	ep          *endpoint
}

// webrtcManager manages WebRTC connections for magicsock.
type webrtcManager struct {
	logf logger.Logf
	conn *Conn // parent magicsock.Conn

	mu                        sync.Mutex
	peerConnectionsByEndpoint map[*endpoint]*webrtcPeerState
	peerConnectionsByDisco    map[key.DiscoPublic]*webrtcPeerState

	signalingClient *signalingClient

	// Control channels
	startConnectionCh chan *endpoint
	connectionReadyCh chan webrtcConnectionReadyEvent
	closeCh           chan struct{}
	runLoopStoppedCh  chan struct{}

	// WebRTC API configuration
	api *webrtc.API
}

// Ensure webrtcManager implements rtclib.SignalHandler interface.
var _ rtclib.SignalHandler = (*webrtcManager)(nil)

// newWebRTCManager creates a new WebRTC manager.
func newWebRTCManager(c *Conn, signalingURL string) *webrtcManager {
	// Configure WebRTC with STUN only
	settingEngine := webrtc.SettingEngine{}

	// Create MediaEngine (required even though we only use DataChannel)
	mediaEngine := &webrtc.MediaEngine{}

	// Create API with setting engine
	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
		webrtc.WithMediaEngine(mediaEngine),
	)

	mgr := &webrtcManager{
		logf:                      c.logf,
		conn:                      c,
		peerConnectionsByEndpoint: make(map[*endpoint]*webrtcPeerState),
		peerConnectionsByDisco:    make(map[key.DiscoPublic]*webrtcPeerState),
		startConnectionCh:         make(chan *endpoint, 256),
		connectionReadyCh:         make(chan webrtcConnectionReadyEvent, 16),
		closeCh:                   make(chan struct{}),
		runLoopStoppedCh:          make(chan struct{}),
		api:                       api,
	}

	// Create and start signaling client
	mgr.signalingClient = newSignalingClient(signalingURL, c.logf)
	if err := mgr.signalingClient.Start(mgr); err != nil {
		c.logf("webrtc: failed to start signaling client: %v", err)
		return nil
	}

	// Start event loop
	go mgr.runLoop()

	return mgr
}

// close shuts down the WebRTC manager.
func (m *webrtcManager) close() error {
	// Close signaling client first to stop new messages
	if m.signalingClient != nil {
		if err := m.signalingClient.Close(); err != nil {
			m.logf("webrtc: signaling client close error: %v", err)
		}
	}

	// Signal runLoop to stop
	close(m.closeCh)

	// Wait for runLoop to finish with timeout
	select {
	case <-m.runLoopStoppedCh:
	case <-time.After(2 * time.Second):
		m.logf("webrtc: close timed out, forcing shutdown")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close all peer connections
	for _, ps := range m.peerConnectionsByEndpoint {
		if ps.peerConn != nil {
			ps.peerConn.Close()
		}
	}
	m.peerConnectionsByEndpoint = nil
	m.peerConnectionsByDisco = nil

	return nil
}

// startConnection initiates a WebRTC connection to an endpoint.
func (m *webrtcManager) startConnection(ep *endpoint) {
	select {
	case m.startConnectionCh <- ep:
	case <-m.closeCh:
	default:
		m.logf("webrtc: startConnection queue full for %v", ep.nodeAddr)
	}
}

// getDataChannel returns the data channel for a peer, or nil if not open.
func (m *webrtcManager) getDataChannel(disco key.DiscoPublic) *webrtc.DataChannel {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.peerConnectionsByDisco[disco]
	if !ok || ps.dataChannel == nil {
		return nil
	}

	if ps.dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
		return ps.dataChannel
	}

	return nil
}

// getRemoteAddr returns the actual remote address for a WebRTC peer connection.
func (m *webrtcManager) getRemoteAddr(disco key.DiscoPublic) netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ps, ok := m.peerConnectionsByDisco[disco]; ok && ps.state == webrtcStateConnected {
		return ps.remoteAddr
	}
	return netip.AddrPort{}
}

// runLoop is the main event loop for the WebRTC manager.
func (m *webrtcManager) runLoop() {
	defer close(m.runLoopStoppedCh)

	for {
		select {
		case ep := <-m.startConnectionCh:
			m.handleStartConnection(ep)

		case event := <-m.connectionReadyCh:
			m.handleConnectionReady(event)

		case <-m.closeCh:
			return
		}
	}
}

// handleStartConnection creates a new WebRTC connection to an endpoint.
func (m *webrtcManager) handleStartConnection(ep *endpoint) {
	m.mu.Lock()

	// Check if we already have a connection
	if ps, exists := m.peerConnectionsByEndpoint[ep]; exists {
		if ps.state == webrtcStateConnecting || ps.state == webrtcStateConnected {
			m.mu.Unlock()
			return
		}
	}

	// Get disco keys
	localDisco := m.conn.DiscoPublicKey()
	disco := ep.disco.Load()
	if disco == nil {
		m.mu.Unlock()
		m.logf("webrtc: cannot start connection, peer has no disco key")
		return
	}
	remoteDisco := disco.key
	m.logf("webrtc: starting connection to peer %v (disco %v)", ep.nodeAddr, remoteDisco.ShortString())

	m.mu.Unlock()

	// Create peer connection
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
		ICETransportPolicy: webrtc.ICETransportPolicyAll,
	}

	peerConn, err := m.api.NewPeerConnection(config)
	if err != nil {
		m.logf("webrtc: failed to create peer connection: %v", err)
		return
	}

	ps := &webrtcPeerState{
		ep:            ep,
		peerConn:      peerConn,
		localDisco:    localDisco,
		remoteDisco:   remoteDisco,
		remoteNodeKey: ep.publicKey,
		state:         webrtcStateConnecting,
		createdAt:     time.Now(),
	}

	// Store peer state
	m.mu.Lock()
	m.peerConnectionsByEndpoint[ep] = ps
	m.peerConnectionsByDisco[remoteDisco] = ps
	m.mu.Unlock()

	// Set up connection state handler
	peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		m.handleConnectionStateChange(ps, state)
	})

	// Set up ICE candidate handler
	peerConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			m.handleLocalICECandidate(ps, candidate)
		}
	})

	// Create data channel
	dataChannel, err := peerConn.CreateDataChannel("tailscale-wg", nil)
	if err != nil {
		m.logf("webrtc: failed to create data channel: %v", err)
		peerConn.Close()
		return
	}

	ps.dataChannel = dataChannel

	// Set up data channel handlers
	dataChannel.OnOpen(func() {
		m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())
		m.connectionReadyCh <- webrtcConnectionReadyEvent{
			remoteDisco: remoteDisco,
			ep:          ep,
		}
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		m.handleDataChannelMessage(ps, msg.Data)
	})

	dataChannel.OnError(func(err error) {
		m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
	})

	// Create and send offer
	offer, err := peerConn.CreateOffer(nil)
	if err != nil {
		m.logf("webrtc: failed to create offer: %v", err)
		peerConn.Close()
		return
	}

	if err := peerConn.SetLocalDescription(offer); err != nil {
		m.logf("webrtc: failed to set local description: %v", err)
		peerConn.Close()
		return
	}

	// Send offer via signaling
	if err := m.signalingClient.Offer(localDisco.String(), remoteDisco.String(), &offer); err != nil {
		m.logf("webrtc: failed to send offer: %v", err)
		peerConn.Close()
		return
	}

	m.logf("webrtc: sent offer to peer %v", remoteDisco.ShortString())
}

// HandleOffer implements rtclib.SignalHandler.
func (m *webrtcManager) HandleOffer(from, to string, offer *webrtc.SessionDescription) {
	m.logf("webrtc: received offer from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteOffer(remoteDisco, offer)
}

// HandleAnswer implements rtclib.SignalHandler.
func (m *webrtcManager) HandleAnswer(from, to string, answer *webrtc.SessionDescription) {
	m.logf("webrtc: received answer from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteAnswer(remoteDisco, answer)
}

// HandleCandidate implements rtclib.SignalHandler.
func (m *webrtcManager) HandleCandidate(from, to string, candidate *webrtc.ICECandidateInit) {
	m.logf("webrtc: received candidate from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteCandidate(remoteDisco, candidate)
}

// handleRemoteOffer processes an incoming offer from a peer.
func (m *webrtcManager) handleRemoteOffer(remoteDisco key.DiscoPublic, offer *webrtc.SessionDescription) {

	// For incoming connections, we need to find the endpoint by disco key
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	m.mu.Unlock()

	if !exists {
		// We received an offer but don't have a connection yet.
		// This happens when the remote peer initiated first (glare scenario).
		// Find the endpoint by disco key and create peer connection state.
		ep := m.conn.findEndpointByDisco(remoteDisco)
		if ep == nil {
			m.logf("webrtc: received offer from unknown peer %v with no endpoint", remoteDisco.ShortString())
			return
		}

		m.logf("webrtc: received offer from peer %v, creating answerer connection", remoteDisco.ShortString())

		// Create peer connection for incoming offer
		config := webrtc.Configuration{
			ICEServers: []webrtc.ICEServer{
				{
					URLs: []string{"stun:stun.l.google.com:19302"},
				},
			},
			ICETransportPolicy: webrtc.ICETransportPolicyAll,
		}

		peerConn, err := m.api.NewPeerConnection(config)
		if err != nil {
			m.logf("webrtc: failed to create peer connection for incoming offer: %v", err)
			return
		}

		localDisco := m.conn.DiscoPublicKey()
		ps = &webrtcPeerState{
			ep:            ep,
			peerConn:      peerConn,
			localDisco:    localDisco,
			remoteDisco:   remoteDisco,
			remoteNodeKey: ep.publicKey,
			state:         webrtcStateConnecting,
			createdAt:     time.Now(),
		}

		// Store peer state
		m.mu.Lock()
		m.peerConnectionsByEndpoint[ep] = ps
		m.peerConnectionsByDisco[remoteDisco] = ps
		m.mu.Unlock()

		// Set up connection state handler
		peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			m.handleConnectionStateChange(ps, state)
		})

		// Set up ICE candidate handler
		peerConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
			if candidate != nil {
				m.handleLocalICECandidate(ps, candidate)
			}
		})

		// Set up data channel handler (for answerer, we wait for the data channel from offerer)
		peerConn.OnDataChannel(func(dc *webrtc.DataChannel) {
			m.logf("webrtc: received data channel from peer %v", remoteDisco.ShortString())
			ps.dataChannel = dc

			dc.OnOpen(func() {
				m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())
				m.connectionReadyCh <- webrtcConnectionReadyEvent{
					remoteDisco: remoteDisco,
					ep:          ep,
				}
			})

			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				m.handleDataChannelMessage(ps, msg.Data)
			})

			dc.OnError(func(err error) {
				m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
			})
		})
	}

	if err := ps.peerConn.SetRemoteDescription(*offer); err != nil {
		m.logf("webrtc: failed to set remote description: %v", err)
		return
	}

	// Create answer
	answer, err := ps.peerConn.CreateAnswer(nil)
	if err != nil {
		m.logf("webrtc: failed to create answer: %v", err)
		return
	}

	if err := ps.peerConn.SetLocalDescription(answer); err != nil {
		m.logf("webrtc: failed to set local description: %v", err)
		return
	}

	// Send answer via signaling
	if err := m.signalingClient.Answer(ps.localDisco.String(), remoteDisco.String(), &answer); err != nil {
		m.logf("webrtc: failed to send answer: %v", err)
		return
	}

	m.logf("webrtc: sent answer to peer %v", remoteDisco.ShortString())
}

// handleRemoteAnswer processes an incoming answer from a peer.
func (m *webrtcManager) handleRemoteAnswer(remoteDisco key.DiscoPublic, answer *webrtc.SessionDescription) {
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	m.mu.Unlock()

	if !exists {
		m.logf("webrtc: received answer from unknown peer %v", remoteDisco.ShortString())
		return
	}

	if err := ps.peerConn.SetRemoteDescription(*answer); err != nil {
		m.logf("webrtc: failed to set remote description: %v", err)
		return
	}

	m.logf("webrtc: set remote description for peer %v", remoteDisco.ShortString())
}

// handleRemoteCandidate processes an incoming ICE candidate from a peer.
func (m *webrtcManager) handleRemoteCandidate(remoteDisco key.DiscoPublic, candidate *webrtc.ICECandidateInit) {
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	m.mu.Unlock()

	if !exists {
		m.logf("webrtc: received candidate from unknown peer %v", remoteDisco.ShortString())
		return
	}

	// Try to extract the remote address from the candidate string
	// Candidate format: "candidate:... udp ... <ip> <port> typ ..."
	if candidate.Candidate != "" {
		if addr := parseICECandidateAddr(candidate.Candidate); addr.IsValid() {
			m.mu.Lock()
			ps.remoteAddr = addr
			m.mu.Unlock()
			m.logf("webrtc: peer %v candidate address: %v", remoteDisco.ShortString(), addr)
		}
	}

	if err := ps.peerConn.AddICECandidate(*candidate); err != nil {
		m.logf("webrtc: failed to add ICE candidate: %v", err)
		return
	}

	m.logf("webrtc: added ICE candidate for peer %v", remoteDisco.ShortString())
}

// parseICECandidateAddr extracts the IP:port from an ICE candidate SDP string.
// Example candidate: "candidate:1234 1 udp 2130706431 192.168.1.100 54321 typ host"
func parseICECandidateAddr(candidate string) netip.AddrPort {
	fields := strings.Fields(candidate)
	// Format: candidate:<foundation> <component> <protocol> <priority> <ip> <port> typ <type>
	if len(fields) < 7 {
		return netip.AddrPort{}
	}

	ip := fields[4]
	port := fields[5]

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}
	}

	var portNum uint16
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		return netip.AddrPort{}
	}

	return netip.AddrPortFrom(addr, portNum)
}

// handleLocalICECandidate sends a local ICE candidate to a peer via signaling.
func (m *webrtcManager) handleLocalICECandidate(ps *webrtcPeerState, candidate *webrtc.ICECandidate) {
	candidateInit := candidate.ToJSON()
	if err := m.signalingClient.Candidate(ps.localDisco.String(), ps.remoteDisco.String(), &candidateInit); err != nil {
		m.logf("webrtc: failed to send candidate: %v", err)
		return
	}

	m.logf("webrtc: sent ICE candidate to peer %v", ps.remoteDisco.ShortString())
}

// handleConnectionStateChange handles WebRTC connection state changes.
func (m *webrtcManager) handleConnectionStateChange(ps *webrtcPeerState, state webrtc.PeerConnectionState) {
	m.logf("webrtc: connection state changed to %s for peer %v", state.String(), ps.remoteDisco.ShortString())

	m.mu.Lock()
	defer m.mu.Unlock()

	switch state {
	case webrtc.PeerConnectionStateConnected:
		ps.state = webrtcStateConnected
	case webrtc.PeerConnectionStateFailed:
		ps.state = webrtcStateFailed
		ps.lastError = errors.New("connection failed")
	case webrtc.PeerConnectionStateClosed:
		ps.state = webrtcStateClosed
	case webrtc.PeerConnectionStateDisconnected:
		// Transient state, keep current state
	}
}

// handleConnectionReady marks a WebRTC connection as ready and updates endpoint.
func (m *webrtcManager) handleConnectionReady(event webrtcConnectionReadyEvent) {
	m.logf("webrtc: connection ready for peer %v", event.remoteDisco.ShortString())

	// Update endpoint to use WebRTC path
	event.ep.mu.Lock()
	defer event.ep.mu.Unlock()

	// Use a fixed port number for WebRTC connections (similar to DERP)
	// The magic IP identifies this as WebRTC, not UDP
	webrtcAddr := addrQuality{
		epAddr: epAddr{
			ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, 12345),
		},
		latency: 0, // Will be determined by disco pings, same as DERP
	}

	// Set as bestAddr if better than current
	now := mono.Now()
	if betterAddr(webrtcAddr, event.ep.bestAddr) {
		event.ep.bestAddr = webrtcAddr
		event.ep.bestAddrAt = now
		event.ep.trustBestAddrUntil = now.Add(5 * time.Minute)
		m.logf("webrtc: updated endpoint %v with WebRTC path", event.ep.nodeAddr)
	}
}

// handleDataChannelMessage processes incoming data from a WebRTC data channel.
func (m *webrtcManager) handleDataChannelMessage(ps *webrtcPeerState, data []byte) {
	m.conn.receiveWebRTC(data, ps.remoteNodeKey)
}

// sendPacket sends a packet over a WebRTC data channel.
func (m *webrtcManager) sendPacket(disco key.DiscoPublic, b []byte) error {
	dc := m.getDataChannel(disco)
	if dc == nil {
		return errors.New("no WebRTC connection")
	}

	if dc.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("data channel not open")
	}

	if err := dc.Send(b); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return errors.New("data channel closed")
		}
		return fmt.Errorf("send failed: %w", err)
	}

	return nil
}

// receiveWebRTC reads a packet from the WebRTC receive channel.
// It is called by wireguard-go through the conn.Bind interface.
func (c *connBind) receiveWebRTC(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for wr := range c.webrtcRecvCh {
		if c.isClosed() {
			break
		}
		n, ep := c.processWebRTCReadResult(wr, buffs[0])
		if n == 0 {
			// No data read occurred. Wait for another packet.
			continue
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
	return 0, net.ErrClosed
}
