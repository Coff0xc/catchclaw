package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍GatewayWSClient manages a WebSocket connection to OpenClaw Gateway
type GatewayWSClient struct {
	conn          *websocket.Conn
	mu            sync.Mutex
	msgID         int
	timeout       time.Duration
	authenticated bool   // true if challenge-response completed
	challengeID   string // nonce from connect.challenge (empty if no challenge received)
}

// WSMessage represents a Gateway WS protocol message
type WSMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *WSError        `json:"error,omitempty"`
}

type WSError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// NewGatewayWSClient connects to the Gateway WS endpoint
func NewGatewayWSClient(target Target, token string, timeout time.Duration) (*GatewayWSClient, error) {
	return NewGatewayWSClientWithOrigin(target, token, timeout, "")
}

// NewGatewayWSClientWithOrigin connects with a custom Origin header for CSWSH testing
func NewGatewayWSClientWithOrigin(target Target, token string, timeout time.Duration, origin string) (*GatewayWSClient, error) {
	wsURL := target.WsURL()
	dialer := WsDialer(timeout)

	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		headers.Set("Origin", origin)
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws connect failed (HTTP %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("ws connect failed: %w", err)
	}

	client := &GatewayWSClient{
		conn:    conn,
		timeout: timeout,
	}

	// Read the initial message — OpenClaw sends connect.challenge as the first frame
	// Two known formats:
	//   1. {"method":"connect.challenge","params":{"nonce":"..."}}
	//   2. {"type":"event","event":"connect.challenge","payload":{"nonce":"...","ts":...}}
	client.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var initMsg map[string]interface{}
	if err := client.conn.ReadJSON(&initMsg); err == nil {
		isChallenge := false

		// Format 1: method-based
		if method, ok := initMsg["method"].(string); ok && method == "connect.challenge" {
			isChallenge = true
			if params, ok := initMsg["params"].(map[string]interface{}); ok {
				if nonce, ok := params["nonce"].(string); ok {
					client.challengeID = nonce
				} else if challenge, ok := params["challenge"].(string); ok {
					client.challengeID = challenge
				}
			}
			if result, ok := initMsg["result"].(map[string]interface{}); ok {
				if nonce, ok := result["nonce"].(string); ok && client.challengeID == "" {
					client.challengeID = nonce
				}
			}
		}

		// Format 2: event-based ({"type":"event","event":"connect.challenge","payload":{...}})
		if evt, ok := initMsg["event"].(string); ok && evt == "connect.challenge" {
			isChallenge = true
			if payload, ok := initMsg["payload"].(map[string]interface{}); ok {
				if nonce, ok := payload["nonce"].(string); ok {
					client.challengeID = nonce
				}
			}
		}

		// Format 3: raw string check fallback
		if !isChallenge {
			raw, _ := json.Marshal(initMsg)
			if strings.Contains(string(raw), "connect.challenge") {
				isChallenge = true
			}
		}

		if isChallenge {
			if client.challengeID == "" {
				client.challengeID = "challenge-received"
			}
			fmt.Printf("  [ws] Challenge gate active (nonce: %s)\n", Truncate(client.challengeID, 16))
		} else {
			// No challenge — connection is directly authenticated
			client.authenticated = true
		}
	}
	// Reset deadline
	client.conn.SetReadDeadline(time.Time{})

	return client, nil
}

// Call sends a JSON-RPC style method call and waits for response.
// Returns error if the connection is behind a challenge gate and not authenticated.
func (c *GatewayWSClient) Call(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	c.msgID++
	id := c.msgID
	c.mu.Unlock()

	var paramsRaw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		paramsRaw = b
	}

	msg := WSMessage{
		ID:     id,
		Method: method,
		Params: paramsRaw,
	}

	c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := c.conn.WriteJSON(msg); err != nil {
		return nil, fmt.Errorf("ws write: %w", err)
	}

	// Read responses until we get our ID back
	c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	for {
		// Read raw message first to detect both RPC and event-format challenges
		_, rawBytes, err := c.conn.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("ws read: %w", err)
		}

		// Check for event-format challenge: {"type":"event","event":"connect.challenge",...}
		var rawMap map[string]interface{}
		if json.Unmarshal(rawBytes, &rawMap) == nil {
			if evt, ok := rawMap["event"].(string); ok && evt == "connect.challenge" {
				c.authenticated = false
				if payload, ok := rawMap["payload"].(map[string]interface{}); ok {
					if nonce, ok := payload["nonce"].(string); ok && c.challengeID == "" {
						c.challengeID = nonce
					}
				}
				return nil, fmt.Errorf("challenge gate: server requires authentication (method %s blocked)", method)
			}
		}

		var resp WSMessage
		if err := json.Unmarshal(rawBytes, &resp); err != nil {
			return nil, fmt.Errorf("ws read: failed to parse response: %w", err)
		}

		// Filter out method-format challenge messages
		if resp.Method == "connect.challenge" {
			c.authenticated = false
			if c.challengeID == "" {
				var challengeParams map[string]interface{}
				if json.Unmarshal(resp.Params, &challengeParams) == nil {
					if nonce, ok := challengeParams["nonce"].(string); ok {
						c.challengeID = nonce
					}
				}
			}
			return nil, fmt.Errorf("challenge gate: server requires authentication (method %s blocked)", method)
		}

		if resp.ID == id {
			if resp.Error != nil {
				return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			// Verify the result is not a challenge nonce masquerading as a response
			if c.challengeID != "" && resp.Result != nil {
				resultStr := string(resp.Result)
				if strings.Contains(resultStr, c.challengeID) {
					return nil, fmt.Errorf("challenge gate: response contains challenge nonce, not real data")
				}
			}
			// Additional defense: detect challenge-like responses even without a known nonce.
			// Some servers echo back a challenge object with matching ID but no Method field.
			if resp.Result != nil {
				resultStr := string(resp.Result)
				if strings.Contains(resultStr, "connect.challenge") ||
					strings.Contains(resultStr, `"nonce"`) ||
					strings.Contains(resultStr, "challenge_required") {
					c.authenticated = false
					return nil, fmt.Errorf("challenge gate: response contains challenge indicators, not real data")
				}
			}
			c.authenticated = true
			return resp.Result, nil
		}
		// Skip push messages / events with different IDs
	}
}

// CallRaw sends a raw JSON message and reads one response.
// Filters out challenge messages.
func (c *GatewayWSClient) CallRaw(data []byte) ([]byte, error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return nil, err
	}
	c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return msg, err
	}

	// Check if response is a challenge message (method or event format)
	var parsed map[string]interface{}
	if json.Unmarshal(msg, &parsed) == nil {
		if method, ok := parsed["method"].(string); ok && method == "connect.challenge" {
			return nil, fmt.Errorf("challenge gate: raw call blocked by authentication requirement")
		}
		if evt, ok := parsed["event"].(string); ok && evt == "connect.challenge" {
			return nil, fmt.Errorf("challenge gate: raw call blocked by authentication requirement")
		}
	}
	// Check if response contains only the challenge nonce
	if c.challengeID != "" && strings.Contains(string(msg), c.challengeID) {
		return nil, fmt.Errorf("challenge gate: response is challenge nonce, not real data")
	}

	return msg, nil
}

// IsAuthenticated returns true if the WS connection has passed the challenge gate
func (c *GatewayWSClient) IsAuthenticated() bool {
	return c.authenticated
}

// ChallengeID returns the challenge nonce if one was received, empty string otherwise
func (c *GatewayWSClient) ChallengeID() string {
	return c.challengeID
}

// HasChallengeGate returns true if the server sent a connect.challenge on connect
func (c *GatewayWSClient) HasChallengeGate() bool {
	return c.challengeID != ""
}

// Close closes the WebSocket connection
func (c *GatewayWSClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
