VERSION   := 4.0.0
BINARY    := lobster-guard
MODULE    := github.com/coff0xc/lobster-guard
BUILDDIR  := dist
LDFLAGS   := -s -w

# 默认: 构建当前平台
.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/lobster-guard/

# 交叉编译全平台
.PHONY: release
release: clean
	@mkdir -p $(BUILDDIR)
	@echo ">>> 构建 Windows amd64 ..."
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-windows-amd64.exe ./cmd/lobster-guard/
	@echo ">>> 构建 Linux amd64 ..."
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-linux-amd64 ./cmd/lobster-guard/
	@echo ">>> 构建 Linux arm64 ..."
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-linux-arm64 ./cmd/lobster-guard/
	@echo ">>> 构建 macOS amd64 ..."
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-darwin-amd64 ./cmd/lobster-guard/
	@echo ">>> 构建 macOS arm64 (Apple Silicon) ..."
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-darwin-arm64 ./cmd/lobster-guard/
	@echo ">>> 全平台构建完成"

# 打包发行包 (每个平台一个 zip/tar.gz)
.PHONY: dist
dist: release
	@echo ">>> 打包发行包 ..."
	@cd $(BUILDDIR) && ../scripts/package.sh $(VERSION)
	@echo ">>> 打包完成, 输出目录: $(BUILDDIR)/"

# 清理
.PHONY: clean
clean:
	rm -rf $(BUILDDIR)
	rm -f $(BINARY) $(BINARY).exe

# 测试
.PHONY: test
test:
	go test ./...
	go vet ./...

# 快速发布 (构建+打包+校验)
.PHONY: all
all: test dist checksum
	@echo ">>> 全部完成"

# 生成校验和
.PHONY: checksum
checksum:
	@cd $(BUILDDIR) && sha256sum *.zip *.tar.gz 2>/dev/null > SHA256SUMS.txt || true
	@echo ">>> 校验和: $(BUILDDIR)/SHA256SUMS.txt"
