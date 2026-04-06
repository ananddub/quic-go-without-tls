package handshake

import (
	"context"
	"crypto"
	"crypto/tls"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// noTLSSalt is used to derive 1-RTT keys in no-TLS mode.
// This is a well-known value, so no-TLS mode provides no confidentiality.
// It only provides the QUIC wire format compatibility.
var noTLSSalt = []byte{0x6e, 0x6f, 0x2d, 0x74, 0x6c, 0x73, 0x2d, 0x71, 0x75, 0x69, 0x63, 0x2d, 0x73, 0x61, 0x6c, 0x74, 0x76, 0x31, 0x2e, 0x30} // "no-tls-quic-saltv1.0"

// noTLSCryptoSetup implements CryptoSetup without TLS.
// Keys are derived from the connection ID (well-known, no confidentiality).
// Transport parameters are exchanged via Initial CRYPTO frames.
type noTLSCryptoSetup struct {
	connID protocol.ConnectionID

	events []Event

	version protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	rttStats *utils.RTTStats
	qlogger  qlogwriter.Recorder
	logger   utils.Logger

	perspective protocol.Perspective

	handshakeCompleteTime time.Time

	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT atomic.Bool

	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool

	handshakeDone bool
	closed        bool
}

var _ CryptoSetup = &noTLSCryptoSetup{}

// NewNoTLSCryptoSetupClient creates a no-TLS crypto setup for the client.
func NewNoTLSCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
) CryptoSetup {
	return newNoTLSCryptoSetup(connID, tp, rttStats, qlogger, logger, protocol.PerspectiveClient, version)
}

// NewNoTLSCryptoSetupServer creates a no-TLS crypto setup for the server.
func NewNoTLSCryptoSetupServer(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
) CryptoSetup {
	return newNoTLSCryptoSetup(connID, tp, rttStats, qlogger, logger, protocol.PerspectiveServer, version)
}

func newNoTLSCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.Version,
) *noTLSCryptoSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
	return &noTLSCryptoSetup{
		connID:        connID,
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		aead:          newUpdatableAEAD(rttStats, qlogger, logger, version),
		events:        make([]Event, 0, 16),
		ourParams:     tp,
		rttStats:      rttStats,
		qlogger:       qlogger,
		logger:        logger,
		perspective:   perspective,
		version:       version,
	}
}

func (h *noTLSCryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	h.connID = id
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
}

func (h *noTLSCryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

// StartHandshake starts the no-TLS handshake.
// It sends our transport parameters as Initial CRYPTO data and sets up handshake keys.
func (h *noTLSCryptoSetup) StartHandshake(_ context.Context) error {
	// Send our transport parameters in the Initial CRYPTO stream.
	data := h.ourParams.Marshal(h.perspective)
	h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: data})

	// Set up handshake-level keys derived from the connection ID.
	h.install1RTTKeys()

	h.logger.Debugf("No-TLS mode: sent transport parameters, installed 1-RTT keys")
	return nil
}

// install1RTTKeys derives and installs 1-RTT encryption keys from the connection ID.
// Since both sides know the connection ID, they can derive the same keys.
func (h *noTLSCryptoSetup) install1RTTKeys() {
	suite := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)

	// Derive client and server secrets from the connection ID using a no-TLS-specific salt.
	initialSecret := hkdf.Extract(crypto.SHA256.New, h.connID.Bytes(), noTLSSalt)
	clientSecret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "no-tls client 1rtt", crypto.SHA256.Size())
	serverSecret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "no-tls server 1rtt", crypto.SHA256.Size())

	var readSecret, writeSecret []byte
	if h.perspective == protocol.PerspectiveClient {
		writeSecret = clientSecret
		readSecret = serverSecret
	} else {
		writeSecret = serverSecret
		readSecret = clientSecret
	}

	// Install 1-RTT keys.
	h.aead.SetReadKey(suite, readSecret)
	h.has1RTTOpener = true
	h.aead.SetWriteKey(suite, writeSecret)
	h.has1RTTSealer = true

	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})

	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.Encryption1RTT, h.perspective),
		})
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.Encryption1RTT, h.perspective.Opposite()),
		})
	}

	if h.logger.Debug() {
		h.logger.Debugf("Installed 1-RTT Read/Write keys (no-TLS mode, using AES_128_GCM_SHA256)")
	}
}

func (h *noTLSCryptoSetup) Close() error {
	h.closed = true
	return nil
}

// HandleMessage handles incoming CRYPTO stream data (peer's transport parameters).
func (h *noTLSCryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if encLevel != protocol.EncryptionInitial {
		// In no-TLS mode, we only expect transport parameters at the Initial level.
		return nil
	}

	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.events = append(h.events, Event{Kind: EventReceivedTransportParameters, TransportParameters: h.peerParams})

	// Once we've received the peer's transport parameters, the handshake is complete.
	if !h.handshakeDone {
		h.handshakeDone = true
		h.handshakeCompleteTime = time.Now()
		h.events = append(h.events, Event{Kind: EventHandshakeComplete})
		h.logger.Debugf("No-TLS handshake complete")
	}
	return nil
}

func (h *noTLSCryptoSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *noTLSCryptoSetup) DiscardInitialKeys() {
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientInitial})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerInitial})
		}
	}
}

func (h *noTLSCryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	var dropped bool
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientHandshake})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerHandshake})
		}
	}
}

func (h *noTLSCryptoSetup) GetSessionTicket() ([]byte, error) {
	// No session tickets in no-TLS mode.
	return nil, nil
}

func (h *noTLSCryptoSetup) ConnectionState() ConnectionState {
	return ConnectionState{
		ConnectionState: tls.ConnectionState{},
		Used0RTT:        h.used0RTT.Load(),
	}
}

func (h *noTLSCryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *noTLSCryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	return nil, ErrKeysDropped
}

func (h *noTLSCryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *noTLSCryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *noTLSCryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *noTLSCryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if h.initialOpener != nil {
		return nil, ErrKeysNotYetAvailable
	}
	return nil, ErrKeysDropped
}

func (h *noTLSCryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *noTLSCryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}
