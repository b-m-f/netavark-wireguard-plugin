
SHELL := /bin/bash

install-deps-ci:
	apt install bats cargo
	cargo install netavark
test:
	bats test/500-plugin.bats
