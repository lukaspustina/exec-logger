all: check build test 

# No check_bcc dependency, because this should run on macOS as well
check:
	cargo check

check_bcc:
	@echo bcc check
	@.ci/scripts/check_bcc.py

build: check_bcc
	cargo build

test: check_bcc
	cargo test

acceptance_tests: BIN=$(shell find target/debug/deps -name "cli_output_tests*" -perm /u+x -type f -exec stat -c '%Y %n' {} \; | sort -nr | awk 'NR==1,NR==3 {print $$2}')
acceptance_tests:
	(sleep 3; ls > /dev/null) & sudo ${BIN} --ignored

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

