all: check

check:
	.ci/scripts/bcc_check.py
	cargo check
