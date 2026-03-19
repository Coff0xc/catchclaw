// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Package payload provides XOR-obfuscated payload storage and runtime decoding.
// Payloads are never stored as plaintext in source — they are XOR-encoded at
// code-generation time and decoded lazily on first access.
package payload

import (
	"encoding/hex"
	"sync"
)

// xorKey is the obfuscation key, injected at generation time.
// Changing this key requires regenerating registry_gen.go.
var xorKey []byte

// entry holds a single obfuscated payload.
type entry struct {
	encoded string   // hex-encoded XOR ciphertext
	once    sync.Once
	decoded string
}

func (e *entry) value() string {
	e.once.Do(func() {
		raw, err := hex.DecodeString(e.encoded)
		if err != nil {
			return
		}
		e.decoded = string(xorDecode(raw, xorKey))
	})
	return e.decoded
}

// registry maps "category.name" → obfuscated entry.
var registry = map[string]*entry{}

// listRegistry maps "category" → ordered list of entry keys.
var listRegistry = map[string][]string{}

// Register is called by generated code to populate the registry.
func Register(key, encoded string) {
	registry[key] = &entry{encoded: encoded}
}

// RegisterList is called by generated code to define ordered lists.
func RegisterList(category string, keys []string) {
	listRegistry[category] = keys
}

// SetKey is called by generated code to set the XOR key.
func SetKey(k []byte) {
	xorKey = k
}

// Get returns a single decoded payload by key (e.g. "xss.script_alert").
// Returns empty string if not found.
func Get(key string) string {
	e, ok := registry[key]
	if !ok {
		return ""
	}
	return e.value()
}

// List returns all decoded payloads for a category in registration order.
// E.g. List("xss") returns all XSS payloads.
func List(category string) []string {
	keys, ok := listRegistry[category]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := Get(k); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// GetAll returns a map of key→decoded payload for a category.
func GetAll(category string) map[string]string {
	keys, ok := listRegistry[category]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = Get(k)
	}
	return out
}

// Has returns true if the key exists in the registry.
func Has(key string) bool {
	_, ok := registry[key]
	return ok
}

func xorDecode(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}
