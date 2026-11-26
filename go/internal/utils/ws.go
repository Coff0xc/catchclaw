package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type WSClient struct {
	conn    *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
}

func WSConnect(wsURL, token string, timeout time.Duration, skipTLSVerify bool) (*WSClient, error) {
	if token != "" {
		sep := "?"
		if strings.Contains(wsURL, "?") {
			sep = "&"
		}
		wsURL = wsURL + sep + "token=" + token
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: skipTLSVerify},
				DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
			},
		},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ws connect: %w", err)
	}

	return &WSClient{
		conn:    conn,
		ctx:     ctx,
		cancel:  cancel,
		timeout: timeout,
	}, nil
}

func (c *WSClient) Close() {
	c.cancel()
	c.conn.Close(websocket.StatusNormalClosure, "done")
}

func (c *WSClient) Call(method string, params map[string]interface{}) (map[string]interface{}, error) {
	id := fmt.Sprintf("%d-%s", time.Now().UnixNano(), method)
	msg := map[string]interface{}{
		"id":     id,
		"method": method,
		"params": params,
	}

	data, _ := json.Marshal(msg)
	writeCtx, writeCancel := context.WithTimeout(c.ctx, c.timeout)
	defer writeCancel()
	if err := c.conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		return nil, fmt.Errorf("ws send: %w", err)
	}

	readCtx, readCancel := context.WithTimeout(c.ctx, c.timeout)
	defer readCancel()

	for {
		_, raw, err := c.conn.Read(readCtx)
		if err != nil {
			return nil, fmt.Errorf("ws read: %w", err)
		}
		var val map[string]interface{}
		if err := json.Unmarshal(raw, &val); err != nil {
			continue
		}
		if val["type"] == "challenge" {
			continue
		}
		if val["id"] == id {
			return val, nil
		}
	}
}

func (c *WSClient) SendRaw(text string) error {
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageText, []byte(text))
}

func (c *WSClient) ReadNext() (string, error) {
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	_, raw, err := c.conn.Read(ctx)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (c *WSClient) HasChallengeGate() bool {
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()
	_, raw, err := c.conn.Read(ctx)
	if err != nil {
		return false
	}
	text := string(raw)
	return strings.Contains(text, "challenge") || strings.Contains(text, "connect.challenge")
}

func WSGatewayURL(baseURL, token string) string {
	wsURL := strings.Replace(baseURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	return wsURL + "/ws/gateway"
}

func BuildWSURL(baseURL, path string) string {
	wsURL := strings.Replace(baseURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	return wsURL + path
}
