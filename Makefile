SHELL := /bin/bash

build:
	cargo build --release

install-deps-ci:
	apt-get update && apt-get install -yy bats curl build-essential gcc make protobuf-compiler
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
	chmod +x rustup.sh
	./rustup.sh -y
	cargo install --git https://github.com/containers/netavark.git
	cargo build --release

.PHONY: test
test: 
	NETAVARK=$$HOME/.cargo/bin/netavark bats test/plugin-tests.bats
