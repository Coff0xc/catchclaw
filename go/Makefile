.PHONY: build release clean install test vet fmt fmt-check ci

BINARY=catchclaw
VERSION=6.0.1

build:
	go build -o $(BINARY) .

release:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-windows-amd64.exe .

install:
	go install .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

ci: vet test fmt-check
	go mod verify
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY) $(BINARY)-*

run: build
	./$(BINARY) $(ARGS)
