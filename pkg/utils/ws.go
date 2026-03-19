package utils

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍WsDialer returns a configured WebSocket dialer
func WsDialer(timeout time.Duration) *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: timeout,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: SkipTLSVerify},
	}
}

// WsConnect connects to a WebSocket with optional Bearer token
func WsConnect(wsURL string, token string, timeout time.Duration) (*websocket.Conn, *http.Response, error) {
	dialer := WsDialer(timeout)
	var headers http.Header
	if token != "" {
		headers = http.Header{}
		headers.Set("Authorization", "Bearer "+token)
	}
	return dialer.Dial(wsURL, headers)
}
