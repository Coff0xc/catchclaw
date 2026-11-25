package osint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxResults  = 100
	QueryMaxLen = 256
	maxBody     = 2 << 20
)

type Host struct {
	Engine  string `json:"engine"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host,omitempty"`
	Org     string `json:"org,omitempty"`
	Product string `json:"product,omitempty"`
	Title   string `json:"title,omitempty"`
}

var client = &http.Client{Timeout: 15 * time.Second}

var Engines = []string{"shodan", "fofa", "hunter"}

var Dorks = map[string]map[string]string{
	"ollama":     {"shodan": "port:11434", "fofa": `app="Ollama"`, "hunter": `web.title="Ollama"`},
	"open-webui": {"shodan": `http.title:"Open WebUI"`, "fofa": `title="Open WebUI"`, "hunter": `web.title="Open WebUI"`},
	"ray":        {"shodan": "port:8265", "fofa": `title="Ray Dashboard"`, "hunter": `web.title="Ray Dashboard"`},
	"mlflow":     {"shodan": `http.title:"MLflow"`, "fofa": `title="MLflow"`, "hunter": `web.title="MLflow"`},
	"gradio":     {"shodan": `http.component:"gradio"`, "fofa": `body="gradio" && port="7860"`, "hunter": `web.body="gradio"`},
	"comfyui":    {"shodan": "port:8188", "fofa": `body="ComfyUI"`, "hunter": `web.body="ComfyUI"`},
	"qdrant":     {"shodan": "port:6333", "fofa": `app="Qdrant"`, "hunter": `web.title="qdrant"`},
	"weaviate":   {"shodan": `http.favicon.hash:1494302000`, "fofa": `app="Weaviate"`, "hunter": `web.title="Weaviate"`},
	"milvus":     {"shodan": "port:19530", "fofa": `app="Milvus"`, "hunter": `web.title="Milvus"`},
	"chromadb":   {"shodan": `http.title:"Chroma"`, "fofa": `app="ChromaDB"`, "hunter": `web.title="Chroma"`},
	"dify":       {"shodan": `http.title:"Dify"`, "fofa": `app="Dify"`, "hunter": `web.title="Dify"`},
	"flowise":    {"shodan": `http.title:"Flowise"`, "fofa": `title="Flowise"`, "hunter": `web.title="Flowise"`},
	"langflow":   {"shodan": `http.title:"Langflow"`, "fofa": `title="Langflow"`, "hunter": `web.title="Langflow"`},
	"vllm":       {"shodan": `http.title:"vLLM"`, "fofa": `title="vLLM"`, "hunter": `web.title="vLLM"`},
	"litellm":    {"shodan": `http.title:"LiteLLM"`, "fofa": `title="LiteLLM"`, "hunter": `web.title="LiteLLM"`},
	"jupyter":    {"shodan": `http.title:"Jupyter"`, "fofa": `app="Jupyter-Notebook"`, "hunter": `web.title="Jupyter Notebook"`},
	"localai":    {"shodan": `http.title:"LocalAI"`, "fofa": `title="LocalAI"`, "hunter": `web.title="LocalAI"`},
	"xinference": {"shodan": "port:9997", "fofa": `title="Xinference"`, "hunter": `web.title="Xinference"`},
	"torchserve": {"shodan": "port:8081,8082 torchserve", "fofa": `app="TorchServe"`, "hunter": `web.title="TorchServe"`},
	"triton":     {"shodan": "port:8000,8001,8002 triton", "fofa": `app="Triton-Inference-Server"`, "hunter": `web.title="Triton"`},
}

func Platforms() []string {
	out := make([]string, 0, len(Dorks))
	for k := range Dorks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func DorkFor(platform, engine string) (string, bool) {
	m, ok := Dorks[strings.ToLower(platform)]
	if !ok {
		return "", false
	}
	q, ok := m[strings.ToLower(engine)]
	return q, ok
}

func Query(engine, q string, size int) ([]Host, error) {
	engine = strings.ToLower(strings.TrimSpace(engine))
	q = strings.TrimSpace(q)
	if q == "" || len(q) > QueryMaxLen {
		return nil, fmt.Errorf("query empty or exceeds %d chars", QueryMaxLen)
	}
	for _, c := range q {
		if c < 0x20 {
			return nil, fmt.Errorf("query contains control character")
		}
	}
	if size <= 0 || size > MaxResults {
		size = MaxResults
	}
	switch engine {
	case "shodan":
		return shodanSearch(q, size)
	case "fofa":
		return fofaSearch(q, size)
	case "hunter":
		return hunterSearch(q, size)
	}
	return nil, fmt.Errorf("unknown engine %q (shodan|fofa|hunter)", engine)
}

func getJSON(u string, v interface{}) error {
	resp, err := client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

func shodanSearch(q string, size int) ([]Host, error) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("SHODAN_API_KEY env not set")
	}
	var r struct {
		Matches []struct {
			IP        string   `json:"ip_str"`
			Port      int      `json:"port"`
			Org       string   `json:"org"`
			Product   string   `json:"product"`
			Hostnames []string `json:"hostnames"`
			HTTP      struct {
				Title string `json:"title"`
			} `json:"http"`
		} `json:"matches"`
	}
	u := "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(key) + "&query=" + url.QueryEscape(q)
	if err := getJSON(u, &r); err != nil {
		return nil, err
	}
	out := make([]Host, 0, len(r.Matches))
	for i, m := range r.Matches {
		if i >= size {
			break
		}
		h := Host{Engine: "shodan", IP: m.IP, Port: m.Port, Org: m.Org, Product: m.Product, Title: m.HTTP.Title}
		if len(m.Hostnames) > 0 {
			h.Host = m.Hostnames[0]
		}
		out = append(out, h)
	}
	return out, nil
}

func fofaSearch(q string, size int) ([]Host, error) {
	email, key := os.Getenv("FOFA_EMAIL"), os.Getenv("FOFA_KEY")
	if email == "" || key == "" {
		return nil, fmt.Errorf("FOFA_EMAIL / FOFA_KEY env not set")
	}
	var r struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
	}
	u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=host,ip,port,title,org",
		url.QueryEscape(email), url.QueryEscape(key),
		base64.StdEncoding.EncodeToString([]byte(q)), size)
	if err := getJSON(u, &r); err != nil {
		return nil, err
	}
	if r.Error {
		return nil, fmt.Errorf("fofa: %s", r.ErrMsg)
	}
	out := make([]Host, 0, len(r.Results))
	for _, row := range r.Results {
		if len(row) < 5 {
			continue
		}
		port, _ := strconv.Atoi(row[2])
		out = append(out, Host{Engine: "fofa", Host: row[0], IP: row[1], Port: port, Title: row[3], Org: row[4]})
	}
	return out, nil
}

func hunterSearch(q string, size int) ([]Host, error) {
	key := os.Getenv("HUNTER_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("HUNTER_API_KEY env not set")
	}
	var r struct {
		Code int    `json:"code"`
		Msg  string `json:"message"`
		Data struct {
			Arr []struct {
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				Domain   string `json:"domain"`
				WebTitle string `json:"web_title"`
				Company  string `json:"company"`
			} `json:"arr"`
		} `json:"data"`
	}
	u := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d&is_web=3",
		url.QueryEscape(key), base64.StdEncoding.EncodeToString([]byte(q)), size)
	if err := getJSON(u, &r); err != nil {
		return nil, err
	}
	if r.Code != 200 {
		return nil, fmt.Errorf("hunter: %s", r.Msg)
	}
	out := make([]Host, 0, len(r.Data.Arr))
	for _, a := range r.Data.Arr {
		out = append(out, Host{Engine: "hunter", IP: a.IP, Port: a.Port, Host: a.Domain, Title: a.WebTitle, Org: a.Company})
	}
	return out, nil
}

func Format(hosts []Host) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-16s %-40s %-6s %-20s %s\n", "IP", "HOST", "PORT", "ORG", "TITLE")
	for _, h := range hosts {
		fmt.Fprintf(&sb, "%-16s %-40s %-6d %-20s %s\n",
			h.IP, trunc(h.Host, 40), h.Port, trunc(h.Org, 20), trunc(h.Title, 60))
	}
	return sb.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
