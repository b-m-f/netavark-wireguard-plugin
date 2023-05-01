SHELL := /bin/bash

install-deps-ci:
	apt-get update && apt-get install -yy bats curl build-essential gcc make protobuf-compiler
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
	chmod +x rustup.sh
	./rustup.sh -y
	cargo install --git https://github.com/containers/netavark.git

.PHONY: test
test: 
	cargo build --release
	ls /home/runner/work/netavark-wireguard-plugin/netavark-wireguard-plugin/
	ls /home/runner/work/netavark-wireguard-plugin/netavark-wireguard-plugin/target/release
	ls /home/runner/work/netavark-wireguard-plugin/
	ls /home/runner/work
	NETAVARK=$$HOME/.cargo/bin/netavark bats test/500-plugin.bats
