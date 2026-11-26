.PHONY: build release test vet fmt fmt-check ci clean install

build:
	cd go && go build -o catchclaw .

release:
	cd go && go build -ldflags="-s -w" -o catchclaw .

test:
	cd go && go test ./...

vet:
	cd go && go vet ./...

fmt:
	cd go && go fmt ./...

fmt-check:
	cd go && files="$$(gofmt -l .)" && if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

ci:
	cd go && $(MAKE) ci

install:
	cd go && go install .

clean:
	cd go && rm -f catchclaw catchclaw.exe catchclaw-*
