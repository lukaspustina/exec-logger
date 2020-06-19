all: check build test tests docs

todos:
	rg --vimgrep -g '!Makefile' -i todo 

# No check_bcc dependency, because this should run on macOS as well
check:
	cargo check

check_bcc:
	.ci/scripts/check_bcc.py

build: check_bcc
	cargo build

test: check_bcc
	cargo test

tests:
	cd $@ && $(MAKE)

clean-package:
	cargo clean -p $$(cargo read-manifest | jq -r .name)

clippy:
	cargo clippy --all --all-targets -- -D warnings $$(source ".clippy.args")

fmt:
	cargo +nightly fmt

duplicate_libs:
	cargo tree -d

.PHONY: tests

