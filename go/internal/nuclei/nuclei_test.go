package nuclei

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchMatcher(t *testing.T) {
	if !matchMatcher(Matcher{Type: "word", Words: []string{"dify"}}, `hello dify`, 200) {
		t.Fatal("word or")
	}
	if matchMatcher(Matcher{Type: "word", Words: []string{"a", "b"}, Condition: "and"}, "a only", 200) {
		t.Fatal("and should fail")
	}
	if !matchMatcher(Matcher{Type: "status", Status: []int{200, 204}}, "x", 204) {
		t.Fatal("status")
	}
	if matchMatcher(Matcher{Type: "status", Status: []int{200}}, "x", 404) {
		t.Fatal("status miss")
	}
}

func TestLoadAndRunTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ping" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"ok":true,"dify":1}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	yml := []byte(`
id: testdify
info:
  name: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/ping"
    matchers:
      - type: word
        words:
          - "dify"
`)
	if err := os.WriteFile(filepath.Join(dir, "t.yaml"), yml, 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(dir)
	if err := r.LoadTemplates(); err != nil {
		t.Fatal(err)
	}
	if len(r.Templates) != 1 || r.Templates[0].ID != "testdify" {
		t.Fatalf("loaded %#v", r.Templates)
	}
	hit, err := r.RunTemplate(r.Templates[0], srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if hit == nil || hit.TemplateID != "testdify" {
		t.Fatalf("hit = %#v", hit)
	}
}
