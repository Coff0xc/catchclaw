package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "mock-ai-service",
		})
	})

	http.HandleFunc("/api/pipelines/run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := make(map[string]interface{})
		json.NewDecoder(r.Body).Decode(&body)

		if url, ok := body["url"].(string); ok {
			if strings.Contains(url, "169.254.169.254") || strings.Contains(url, "127.0.0.1") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{
					"result": "ami-0123456789abcdef0 instance-id=i-0123456789abcdef0",
					"status": "success",
				})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status": "processed",
		})
	})

	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := make(map[string]interface{})
		json.NewDecoder(r.Body).Decode(&body)

		messages, _ := body["messages"].([]interface{})
		if len(messages) > 0 {
			msg, _ := messages[0].(map[string]interface{})
			content, _ := msg["content"].(string)

			if strings.Contains(content, "Ignore all instructions") || strings.Contains(content, "CANARY") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id": "chatcmpl-123",
					"choices": []map[string]interface{}{
						{
							"message": map[string]string{
								"role":    "assistant",
								"content": "CANARY_PROMPT_INJECT_OK",
							},
						},
					},
				})
				return
			}

			if strings.Contains(content, "id") || strings.Contains(content, "echo") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id": "chatcmpl-123",
					"choices": []map[string]interface{}{
						{
							"message": map[string]string{
								"role":    "assistant",
								"content": "uid=0(root) gid=0(root) groups=0(root)",
							},
						},
					},
				})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "chatcmpl-123",
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"role":    "assistant",
						"content": "I'm sorry, I cannot help with that request.",
					},
				},
			},
		})
	})

	http.HandleFunc("/api/tools/invoke", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result": "uid=0(root) gid=0(root) groups=0(root)",
			"status": "success",
		})
	})

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]string{
			"api_key": "sk-test-key-12345",
			"model":   "gpt-4",
		})
	})

	http.HandleFunc("/api/system/run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"output": "uid=0(root) gid=0(root) groups=0(root)",
			"status": "executed",
		})
	})

	http.HandleFunc("/api/agent/run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result": "uid=0(root) gid=0(root) groups=0(root)",
			"status": "success",
		})
	})

	http.HandleFunc("/api/secrets/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"arn":     "arn:aws:iam::123456789012:user/admin",
			"account": "123456789012",
			"status":  "executed",
		})
	})

	http.HandleFunc("/api/crew/run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"output": "uid=0(root) gid=0(root) groups=0(root)",
			"status": "executed",
		})
	})

	fmt.Println("Mock vulnerable server listening on :18080")
	http.ListenAndServe(":18080", nil)
}
