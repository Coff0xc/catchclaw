// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Package api 提供 RESTful HTTP API，供第三方系统集成调用。
// 用法: api.NewServer(cfg).ListenAndServe()
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// ServerConfig 定义 API 服务器配置。
type ServerConfig struct {
	Addr  string // 监听地址，默认 ":9527"
	Token string // 可选 Bearer 认证令牌
}

// Server 提供 RESTful API 服务。
type Server struct {
	cfg   ServerConfig
	mux   *http.ServeMux
	scans *ScanManager
}

// NewServer 创建并初始化 API 服务器。
func NewServer(cfg ServerConfig) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":9527"
	}
	s := &Server{
		cfg:   cfg,
		mux:   http.NewServeMux(),
		scans: NewScanManager(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.cfg.Token != "" {
				got := r.Header.Get("Authorization")
				if got != "Bearer "+s.cfg.Token {
					jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
			}
			h(w, r)
		}
	}

	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/scan", auth(s.handleScan))
	s.mux.HandleFunc("/api/v1/scan/", auth(s.handleScanByID))
	s.mux.HandleFunc("/api/v1/scans", auth(s.handleListScans))
	s.mux.HandleFunc("/api/v1/cve", auth(s.handleCVE))
}

// ListenAndServe 启动 HTTP 服务。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	fmt.Printf("[*] LobsterGuard API 服务启动: http://%s\n", addr)
	fmt.Printf("[*] 接口文档: http://%s/api/v1/health\n", addr)
	return http.Serve(ln, s.mux)
}

func jsonResp(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
