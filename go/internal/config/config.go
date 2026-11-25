package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type LogLevel int

const (
	LogInfo LogLevel = iota
	LogDebug
	LogTrace
	LogWarn
	LogError
	LogQuiet
)

func (l LogLevel) String() string {
	return []string{"info", "debug", "trace", "warn", "error", "quiet"}[l]
}

func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return LogDebug
	case "trace":
		return LogTrace
	case "warn", "warning":
		return LogWarn
	case "error":
		return LogError
	case "quiet", "silent":
		return LogQuiet
	default:
		return LogInfo
	}
}

type ProxyConfig struct {
	HTTP   string `json:"http,omitempty" yaml:"http"`
	HTTPS  string `json:"https,omitempty" yaml:"https"`
	SOCKS5 string `json:"socks5,omitempty" yaml:"socks5"`
}

type GraphConfig struct {
	ExportMermaid bool   `json:"export_mermaid" yaml:"export_mermaid"`
	ExportJSON    bool   `json:"export_json" yaml:"export_json"`
	OutputDir     string `json:"output_dir,omitempty" yaml:"output_dir"`
}

type PayloadConfig struct {
	File           string `json:"file,omitempty" yaml:"file"`
	EnableMutation bool   `json:"enable_mutation" yaml:"enable_mutation"`
}

type TargetConfig struct {
	Host  string `json:"host,omitempty" yaml:"host"`
	Port  int    `json:"port,omitempty" yaml:"port"`
	TLS   bool   `json:"tls,omitempty" yaml:"tls"`
	Token string `json:"token,omitempty" yaml:"token"`
}

type ScannerConfig struct {
	Timeout     int    `json:"timeout,omitempty" yaml:"timeout"`
	Concurrency int    `json:"concurrency,omitempty" yaml:"concurrency"`
	LogLevel    string `json:"log_level,omitempty" yaml:"log_level"`
	Aggressive  bool   `json:"aggressive,omitempty" yaml:"aggressive"`
	CallbackURL string `json:"callback_url,omitempty" yaml:"callback_url"`
}

type ProfileConfig struct {
	Scanner *ScannerConfig `json:"scanner,omitempty" yaml:"scanner"`
	Proxy   *ProxyConfig   `json:"proxy,omitempty" yaml:"proxy"`
	Graph   *GraphConfig   `json:"graph,omitempty" yaml:"graph"`
	Payload *PayloadConfig `json:"payload,omitempty" yaml:"payload"`
}

type FileConfig struct {
	Target   *TargetConfig             `json:"target,omitempty" yaml:"target"`
	Scanner  *ScannerConfig            `json:"scanner,omitempty" yaml:"scanner"`
	Proxy    *ProxyConfig              `json:"proxy,omitempty" yaml:"proxy"`
	Graph    *GraphConfig              `json:"graph,omitempty" yaml:"graph"`
	Payload  *PayloadConfig            `json:"payload,omitempty" yaml:"payload"`
	Profiles map[string]*ProfileConfig `json:"profile,omitempty" yaml:"profile"`
}

type Config struct {
	Token       string
	Timeout     time.Duration
	CallbackURL string
	Concurrency int
	Aggressive  bool
	Quiet       bool
	LogLevel    LogLevel
	Proxy       ProxyConfig
	Graph       GraphConfig
	Payload     PayloadConfig
}

func Default() *Config {
	return &Config{
		Timeout:     10 * time.Second,
		Concurrency: 10,
		LogLevel:    LogInfo,
	}
}

func LoadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	var cfg FileConfig
	switch ext {
	case ".json":
		err = json.Unmarshal(data, &cfg)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &cfg)
	default:
		if err = yaml.Unmarshal(data, &cfg); err != nil {
			err = json.Unmarshal(data, &cfg)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return &cfg, nil
}

func LoadDefault() *FileConfig {
	candidates := []string{"catchclaw.toml", "catchclaw.yaml", "catchclaw.yml", ".catchclaw.toml", ".catchclaw.yaml"}
	for _, c := range candidates {
		if cfg, err := LoadFile(c); err == nil {
			return cfg
		}
	}
	return &FileConfig{}
}

func (fc *FileConfig) ApplyProfile(name string) error {
	profile, ok := fc.Profiles[name]
	if !ok {
		names := make([]string, 0, len(fc.Profiles))
		for k := range fc.Profiles {
			names = append(names, k)
		}
		return fmt.Errorf("profile %q not found. Available: %v", name, names)
	}
	if profile.Scanner != nil {
		fc.Scanner = profile.Scanner
	}
	if profile.Proxy != nil {
		fc.Proxy = profile.Proxy
	}
	if profile.Graph != nil {
		fc.Graph = profile.Graph
	}
	if profile.Payload != nil {
		fc.Payload = profile.Payload
	}
	return nil
}

func (fc *FileConfig) Merge(token string, timeout time.Duration, concurrency int, tls bool, callback string, level LogLevel) *Config {
	cfg := Default()
	if fc.Target != nil && fc.Target.Token != "" && token == "" {
		cfg.Token = fc.Target.Token
	} else {
		cfg.Token = token
	}
	if fc.Scanner != nil {
		if timeout == 0 {
			cfg.Timeout = time.Duration(fc.Scanner.Timeout) * time.Second
			if fc.Scanner.Timeout == 0 {
				cfg.Timeout = 10 * time.Second
			}
		} else {
			cfg.Timeout = timeout
		}
		if concurrency == 0 {
			cfg.Concurrency = fc.Scanner.Concurrency
			if cfg.Concurrency == 0 {
				cfg.Concurrency = 10
			}
		} else {
			cfg.Concurrency = concurrency
		}
		cfg.Aggressive = fc.Scanner.Aggressive
		cfg.CallbackURL = fc.Scanner.CallbackURL
		if level == LogInfo && fc.Scanner.LogLevel != "" {
			cfg.LogLevel = ParseLogLevel(fc.Scanner.LogLevel)
		} else {
			cfg.LogLevel = level
		}
	} else {
		if timeout > 0 {
			cfg.Timeout = timeout
		}
		if concurrency > 0 {
			cfg.Concurrency = concurrency
		}
		cfg.LogLevel = level
	}
	if callback != "" {
		cfg.CallbackURL = callback
	}
	if fc.Proxy != nil {
		cfg.Proxy = *fc.Proxy
	}
	if fc.Graph != nil {
		cfg.Graph = *fc.Graph
	}
	if fc.Payload != nil {
		cfg.Payload = *fc.Payload
	}
	cfg.Quiet = cfg.LogLevel == LogQuiet
	return cfg
}

func (c *Config) HasProxy() bool {
	return c.Proxy.HTTP != "" || c.Proxy.HTTPS != "" || c.Proxy.SOCKS5 != ""
}

func (c *Config) PrimaryProxy() string {
	if c.Proxy.HTTPS != "" {
		return c.Proxy.HTTPS
	}
	if c.Proxy.HTTP != "" {
		return c.Proxy.HTTP
	}
	return c.Proxy.SOCKS5
}
