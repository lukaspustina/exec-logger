all: check build test 

# No check_bcc dependency, because this should run on macOS as well
check:
	cargo check

check_bcc:
	.ci/scripts/check_bcc.py

build: check_bcc
	cargo build

test: check_bcc
	cargo test

clippy:
	cargo clippy --bins --tests --benches --examples --all-features

fmt-check:
	cargo fmt -- --check

fmt:
	cargo fmt



clean-package:
	cargo clean -p $$(cargo read-manifest | jq -r .name)


duplicate_libs:
	cargo tree -d

