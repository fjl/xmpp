package xmpp

import (
	"errors"
)

// StreamInfo contains information about an XMPP connection.
type StreamInfo struct {
	Domain     string   // server hostname
	TLS        bool     // whether stream is connected via TLS
	Mechanisms []string // SASL mechanisms advertised by the server
}

// Auth is implemented by XMPP authentication mechanisms.
type Auth interface {
	// Start begins an authentication with a server.
	// It returns the name of the authentication protocol
	// and optionally data to include in the initial <auth> element
	// sent to the server. It can return proto == "" to indicate
	// that the authentication should be skipped.
	// If Start returns a non-nil error, the authentication
	// attempt is aborted and the connection is closed.
	Start(info *StreamInfo) (proto string, toServer []byte, err error)

	// Next continues the authentication. The server has just sent
	// the fromServer data. If more is true, the server expects a
	// response, which Next should return as toServer; otherwise
	// Next should return toServer == nil.
	// If Next returns a non-nil error, the authentication
	// attempt is aborted and the connection is closed.
	Next(fromServer []byte, more bool) (toServer []byte, err error)
}

// PlainAuth returns an Auth that performs PLAIN authentication with
// the given username and password.
func PlainAuth(user, password string) Auth {
	return &plain{user, password}
}

type plain struct{ user, password string }

func (a *plain) Start(info *StreamInfo) (string, []byte, error) {
	for _, m := range info.Mechanisms {
		if m == "PLAIN" {
			return m, []byte("\x00" + a.user + "\x00" + a.password), nil
		}
	}
	return "", nil, errors.New("server doesn't support PLAIN auth")
}

func (a *plain) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
