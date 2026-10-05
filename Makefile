help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
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
	@cargo clippy --features=rkyv/size_32

fmt: ## Format code (requires nightly)
	@cargo +nightly fmt --all

bench: ## Run benchmarks
	@cargo bench

no-std: ## Verify no_std compatibility
	@rustup target add thumbv6m-none-eabi
	@cargo build --release --no-default-features --features alloc --target thumbv6m-none-eabi
	@cargo build --release --no-default-features --target thumbv6m-none-eabi

doc: ## Generate documentation
	@cargo rustdoc --lib -- --html-in-header katex-header.html -D warnings

doc-internal: ## Generate documentation with private items
	@cargo rustdoc --lib -- --document-private-items -D warnings

doc-local: ## Open local documentation
	@RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps --open

clean: ## Clean build artifacts
	@cargo clean

.PHONY: help test test-32 clippy fmt bench no-std doc doc-internal doc-local clean
