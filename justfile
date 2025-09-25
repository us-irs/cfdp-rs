all: check build embedded clippy fmt docs test coverage

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt --all -- --check

check:
  cargo check --features "serde, defmt"

test:
  cargo nextest r --features "serde, defmt"
  cargo test --doc

build:
  cargo build --features "serde, defmt"

embedded:
  cargo build --target thumbv7em-none-eabihf --no-default-features --features "defmt, packet-buf-1k"

docs:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --features "serde, defmt"

docs-html:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --features "serde, defmt" --open

coverage:
  cargo llvm-cov nextest

coverage-html:
  cargo llvm-cov nextest --html --open
