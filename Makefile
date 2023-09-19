SOURCE_FILES := $(shell test -e src/ && find src -type f)
VERSION := $(shell sed --posix -n 's,^version = \"\(.*\)\",\1,p' Cargo.toml)

policy.wasm: $(SOURCE_FILES) Cargo.*
	cargo build --target=wasm32-wasi --release
	cp target/wasm32-wasi/release/*.wasm policy.wasm

artifacthub-pkg.yml: metadata.yml Cargo.toml
	kwctl scaffold artifacthub --metadata-path metadata.yml --version $(VERSION) \
		--questions-path questions-ui.yml --output artifacthub-pkg.yml

annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -u README.md -o annotated-policy.wasm policy.wasm

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	@echo "Dummy target to allow using the reusable github actions to build, test and release policies"

.PHONY: test
test: fmt lint
	cargo test

.PHONY: clean
clean:
	cargo clean
	rm -f policy.wasm annotated-policy.wasm artifacthub-pkg.yml
