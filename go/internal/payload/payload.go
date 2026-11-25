package payload

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

type Registry struct {
	data map[string][]map[string]string
}

var (
	once     sync.Once
	instance *Registry
)

func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}
	r := &Registry{data: make(map[string][]map[string]string)}
	for cat, items := range raw {
		if list, ok := items.([]interface{}); ok {
			for _, item := range list {
				if m, ok := item.(map[string]interface{}); ok {
					entry := make(map[string]string)
					for k, v := range m {
						if s, ok := v.(string); ok {
							entry[k] = s
						}
					}
					r.data[cat] = append(r.data[cat], entry)
				}
			}
		}
	}
	return r, nil
}

func LoadFile(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("yaml parse %s: %w", path, err)
	}
	r := &Registry{data: make(map[string][]map[string]string)}
	for cat, items := range raw {
		switch v := items.(type) {
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					r.data[cat] = append(r.data[cat], map[string]string{"value": s})
				} else if m, ok := item.(map[string]interface{}); ok {
					entry := make(map[string]string)
					for k, val := range m {
						if sv, ok := val.(string); ok {
							entry[k] = sv
						}
					}
					r.data[cat] = append(r.data[cat], entry)
				}
			}
		case map[string]interface{}:
			entry := make(map[string]string)
			for k, val := range v {
				if sv, ok := val.(string); ok {
					entry[k] = sv
				}
			}
			r.data[cat] = append(r.data[cat], entry)
		}
	}
	return r, nil
}

func LoadDir(dir string) (*Registry, error) {
	r := &Registry{data: make(map[string][]map[string]string)}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	ymlFiles, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	files = append(files, ymlFiles...)
	for _, f := range files {
		sub, err := LoadFile(f)
		if err != nil {
			continue
		}
		for cat, entries := range sub.data {
			r.data[cat] = append(r.data[cat], entries...)
		}
	}
	return r, nil
}

func Default() *Registry {
	once.Do(func() {
		candidates := []string{
			"payloads.yaml",
			"../payloads.yaml",
			"../../payloads.yaml",
			"/etc/catchclaw/payloads.yaml",
		}
		for _, c := range candidates {
			if r, err := Load(c); err == nil {
				instance = r
				return
			}
		}
		for _, c := range []string{"payloads", "../payloads", "../../payloads"} {
			if r, err := LoadDir(c); err == nil && len(r.data) > 0 {
				instance = r
				return
			}
		}
		instance = &Registry{data: make(map[string][]map[string]string)}
	})
	return instance
}

func (r *Registry) Get(category string) []string {
	entries, ok := r.data[category]
	if !ok {
		return nil
	}
	var result []string
	for _, e := range entries {
		if v, ok := e["value"]; ok {
			result = append(result, v)
			continue
		}
		for _, v := range e {
			result = append(result, v)
		}
	}
	return result
}

func (r *Registry) GetKeyed(category string) []map[string]string {
	return r.data[category]
}

func (r *Registry) GetValue(category, key string) (string, bool) {
	entries, ok := r.data[category]
	if !ok {
		return "", false
	}
	for _, e := range entries {
		if v, ok := e[key]; ok {
			return v, true
		}
	}
	return "", false
}

func (r *Registry) AllSSRF() []string {
	result := r.Get("ssrf")
	result = append(result, r.Get("aws_imds")...)
	result = append(result, r.Get("aws_imds_v2")...)
	result = append(result, r.Get("gcp_metadata")...)
	result = append(result, r.Get("azure_imds")...)
	result = append(result, r.Get("digitalocean")...)
	result = append(result, r.Get("internal_services")...)
	result = append(result, r.Get("ip_bypass")...)
	result = append(result, r.Get("protocol_smuggling")...)
	result = append(result, r.Get("ipv6_bypass")...)
	result = append(result, r.Get("attachment_ssrf")...)
	return result
}

func (r *Registry) AllPromptInject() []string {
	result := r.Get("prompt_inject")
	result = append(result, r.Get("system_prompt_extract")...)
	result = append(result, r.Get("jailbreak")...)
	result = append(result, r.Get("role_override")...)
	result = append(result, r.Get("context_overflow")...)
	result = append(result, r.Get("request_side_inject")...)
	result = append(result, r.Get("prompt_exploit")...)
	result = append(result, r.Get("indirect_prompt_inject")...)
	return result
}

func (r *Registry) AllCommandInject() []string {
	result := r.Get("command_injection")
	result = append(result, r.Get("shell_metachar")...)
	result = append(result, r.Get("encoding_bypass")...)
	result = append(result, r.Get("safebins_gnu_bypass")...)
	return result
}

func (r *Registry) AllXSS() []string {
	result := r.Get("reflected")
	result = append(result, r.Get("event_handlers")...)
	result = append(result, r.Get("filter_bypass")...)
	result = append(result, r.Get("dom")...)
	result = append(result, r.Get("polyglot")...)
	return result
}

func (r *Registry) AllTemplateInject() []string {
	return r.Get("template_injection")
}

func (r *Registry) AllAuthBypass() []string {
	result := r.Get("token_manipulation")
	result = append(result, r.Get("header_bypass")...)
	result = append(result, r.Get("path_traversal_auth")...)
	result = append(result, r.Get("default_creds")...)
	return result
}

func (r *Registry) DefaultTokens() []string {
	return r.Get("default_tokens")
}

func (r *Registry) Categories() []string {
	var cats []string
	for k := range r.data {
		cats = append(cats, k)
	}
	return cats
}

func (r *Registry) Count() int {
	total := 0
	for _, entries := range r.data {
		total += len(entries)
	}
	return total
}
