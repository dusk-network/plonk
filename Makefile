help: ## Display this help screen
	@grep -h -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run tests
	@cargo test --release
	@cargo test --release --all-features

# criterion's `alloca` compiles C: clang builds it with its own headers.
TEST_32 = CC_i686_unknown_linux_musl=clang \
	CFLAGS_i686_unknown_linux_musl="--target=i686-linux-musl -ffreestanding -nostdinc -isystem $$(clang -print-resource-dir)/include" \
	cargo test --release --target i686-unknown-linux-musl

test-32: ## Run tests on a 32-bit target
	@rustup target add i686-unknown-linux-musl
	@$(TEST_32)
	@# Every feature but `debug`: the dusk-cdf format is not 32-bit safe.
	@$(TEST_32) --features rkyv-impl,legacy-proving

clippy: ## Run clippy
	@cargo clippy --all-features --features rkyv/size_32 --all-targets -- -D warnings
	@cargo clippy --no-default-features -- -D warnings
	@cargo clippy --no-default-features --features alloc -- -D warnings

cq: ## Run code quality checks (formatting + clippy)
	@$(MAKE) fmt CHECK=1
	@$(MAKE) clippy

fmt: ## Format code (requires nightly)
	@rustup component add --toolchain nightly rustfmt 2>/dev/null || true
	@cargo +nightly fmt --all $(if $(CHECK),-- --check,)

bench: ## Run benchmarks
	@cargo bench

build-benches: ## Build benchmarks
	@cargo bench --no-run

run-examples: ## Run the examples
	@cargo run --release --example circuit

no-std: ## Verify no_std compatibility
	@rustup target add thumbv6m-none-eabi
	@cargo build --release --no-default-features --features alloc --target thumbv6m-none-eabi
	@cargo build --release --no-default-features --target thumbv6m-none-eabi
	@cargo check --target thumbv6m-none-eabi --no-default-features --features alloc,rkyv-impl,rkyv/size_32

doc: ## Generate documentation
	@cargo rustdoc --lib -- --html-in-header katex-header.html -D warnings

doc-internal: ## Generate documentation with private items
	@cargo rustdoc --lib -- --document-private-items -D warnings

doc-local: ## Open local documentation
	@RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps --open

clean: ## Clean build artifacts
	@cargo clean

.PHONY: help test test-32 clippy cq fmt bench build-benches run-examples no-std doc doc-internal doc-local clean
