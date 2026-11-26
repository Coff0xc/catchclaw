.PHONY: build release test vet fmt clean install rust-build rust-test rust-clippy rust-fmt rust-clean

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

install:
	cd go && go install .

clean:
	cd go && rm -f catchclaw catchclaw.exe catchclaw-*

# Archived v5.x (Rust). Not the release target.
rust-build:
	cd rust && cargo build

rust-test:
	cd rust && cargo test

rust-clippy:
	cd rust && cargo clippy -- -D warnings

rust-fmt:
	cd rust && cargo fmt -- --check

rust-clean:
	cd rust && cargo clean
