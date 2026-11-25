package scan

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Coff0xc/catchclaw/go/internal/core"
	"github.com/Coff0xc/catchclaw/go/internal/utils"
)

type DiscoveryResult struct {
	Host     string
	Port     int
	Open     bool
	Platform core.Platform
	Banner   string
}

var commonPorts = []int{80, 443, 3000, 3001, 3010, 3080, 4000, 5000, 5001, 5670, 6333, 7860, 7861, 8000, 8001, 8080, 8081, 8188, 8265, 8888, 9380, 9997, 9999, 11434, 19530}

var platformFingerprints = map[core.Platform][]string{
	core.PlatformOpenClaw:    {"/api/version", "/api/config", "/api/health"},
	core.PlatformDify:        {"/api/v1/version", "/health"},
	core.PlatformFastGPT:     {"/api/version", "/healthz"},
	core.PlatformLobeChat:    {"/api/version", "/api/health"},
	core.PlatformNextChat:    {"/api/config"},
	core.PlatformAnythingLLM: {"/api/version", "/api/health"},
	core.PlatformFlowise:     {"/api/v1/version", "/healthz"},
	core.PlatformRagFlow:     {"/api/v1/version", "/health"},
	core.PlatformLibreChat:   {"/api/config", "/health"},
	core.PlatformLangflow:    {"/api/v1/version", "/health"},
	core.PlatformLiteLLM:     {"/health", "/models"},
	core.PlatformOllama:      {"/api/tags"},
	core.PlatformVLLM:        {"/v1/models", "/health"},
	core.PlatformRay:         {"/api/version"},
	core.PlatformMLflow:      {"/health", "/version"},
	core.PlatformGradio:      {"/config", "/info"},
	core.PlatformComfyUI:     {"/system_stats"},
	core.PlatformDBGPT:       {"/api/v1/version"},
	core.PlatformChromaDB:    {"/api/v1/version", "/api/v1/heartbeat"},
	core.PlatformQdrant:      {"/collections"},
	core.PlatformWeaviate:    {"/v1/meta"},
	core.PlatformLocalAI:     {"/v1/models"},
	core.PlatformXinference:  {"/v1/version"},
	core.PlatformJupyter:     {"/api", "/api/status"},
}

func PortScan(host string, ports []int, timeout time.Duration, concurrency int) []int {
	if ports == nil {
		ports = commonPorts
	}
	if concurrency < 1 {
		concurrency = 50
	}

	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), timeout)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			openPorts = append(openPorts, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return openPorts
}

func DetectPlatform(host string, port int, tls bool, timeout time.Duration) (core.Platform, string) {
	baseURL := fmt.Sprintf("http://%s:%d", host, port)
	if tls {
		baseURL = fmt.Sprintf("https://%s:%d", host, port)
	}

	client := utils.BuildClient(timeout, nil)

	for platform, paths := range platformFingerprints {
		for _, path := range paths {
			url := baseURL + path
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			if err != nil {
				continue
			}
			body := string(bodyBytes)

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				lowerBody := strings.ToLower(body)
				switch platform {
				case core.PlatformOpenClaw:
					if strings.Contains(lowerBody, "openclaw") || strings.Contains(lowerBody, "open-webui") || strings.Contains(lowerBody, "ollama") {
						return platform, body
					}
				case core.PlatformDify:
					if strings.Contains(lowerBody, "dify") {
						return platform, body
					}
				case core.PlatformFastGPT:
					if strings.Contains(lowerBody, "fastgpt") || strings.Contains(lowerBody, "fast-gpt") {
						return platform, body
					}
				case core.PlatformLobeChat:
					if strings.Contains(lowerBody, "lobechat") || strings.Contains(lowerBody, "lobe-chat") {
						return platform, body
					}
				case core.PlatformNextChat:
					if strings.Contains(lowerBody, "nextchat") || strings.Contains(lowerBody, "__next_data__") || strings.Contains(lowerBody, "chatgpt-next-web") {
						return platform, body
					}
				case core.PlatformAnythingLLM:
					if strings.Contains(lowerBody, "anythingllm") || strings.Contains(lowerBody, "anything-llm") {
						return platform, body
					}
				case core.PlatformFlowise:
					if strings.Contains(lowerBody, "flowise") || strings.Contains(lowerBody, "flowiseai") {
						return platform, body
					}
				case core.PlatformRagFlow:
					if strings.Contains(lowerBody, "ragflow") || strings.Contains(lowerBody, "rag-flow") {
						return platform, body
					}
				case core.PlatformLibreChat:
					if strings.Contains(lowerBody, "librechat") || strings.Contains(lowerBody, "libre-chat") {
						return platform, body
					}
				case core.PlatformLangflow:
					if strings.Contains(lowerBody, "langflow") || strings.Contains(lowerBody, "lang-flow") {
						return platform, body
					}
				case core.PlatformLiteLLM:
					if strings.Contains(lowerBody, "litellm") || strings.Contains(lowerBody, "lite-llm") {
						return platform, body
					}
				case core.PlatformOllama:
					if strings.Contains(lowerBody, "models") || strings.Contains(lowerBody, "ollama") {
						return platform, body
					}
				case core.PlatformVLLM:
					if strings.Contains(lowerBody, "data") || strings.Contains(lowerBody, "vllm") {
						return platform, body
					}
				case core.PlatformRay:
					if strings.Contains(lowerBody, "ray") {
						return platform, body
					}
				case core.PlatformMLflow:
					if strings.Contains(lowerBody, "mlflow") || strings.Contains(lowerBody, "ok") {
						return platform, body
					}
				case core.PlatformGradio:
					if strings.Contains(lowerBody, "gradio") {
						return platform, body
					}
				case core.PlatformComfyUI:
					if strings.Contains(lowerBody, "comfyui") || strings.Contains(lowerBody, "comfy") {
						return platform, body
					}
				case core.PlatformDBGPT:
					if strings.Contains(lowerBody, "dbgpt") || strings.Contains(lowerBody, "db-gpt") {
						return platform, body
					}
				case core.PlatformChromaDB:
					if strings.Contains(lowerBody, "chroma") {
						return platform, body
					}
				case core.PlatformQdrant:
					if strings.Contains(lowerBody, "qdrant") || strings.Contains(lowerBody, "collections") {
						return platform, body
					}
				case core.PlatformWeaviate:
					if strings.Contains(lowerBody, "weaviate") {
						return platform, body
					}
				case core.PlatformLocalAI:
					if strings.Contains(lowerBody, "localai") || strings.Contains(lowerBody, "local-ai") {
						return platform, body
					}
				case core.PlatformXinference:
					if strings.Contains(lowerBody, "xinference") {
						return platform, body
					}
				case core.PlatformJupyter:
					if strings.Contains(lowerBody, "jupyter") || strings.Contains(lowerBody, "notebook") {
						return platform, body
					}
				}
			}
		}
	}

	return core.PlatformUnknown, ""
}

func DiscoverServices(host string, timeout time.Duration, concurrency int) []DiscoveryResult {
	openPorts := PortScan(host, nil, timeout, concurrency)
	var results []DiscoveryResult

	client := utils.BuildClient(timeout, nil)
	for _, port := range openPorts {
		platform, banner := DetectPlatform(host, port, false, timeout)
		if platform == core.PlatformUnknown {
			baseURL := fmt.Sprintf("http://%s:%d", host, port)
			resp, err := client.Get(baseURL)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				banner = string(bodyBytes)
			}
		}
		results = append(results, DiscoveryResult{
			Host:     host,
			Port:     port,
			Open:     true,
			Platform: platform,
			Banner:   core.TruncateStr(banner, 200),
		})
	}
	return results
}
