all: check build clippy fmt docs test coverage

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt --all -- --check

check:
  cargo check --all-features

test:
  cargo nextest r --all-features
  cargo test --doc

build:
  cargo build --all-features

embedded:
  cargo build --target thumbv7em-none-eabihf --no-default-features --features "alloc"

docs:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --all-features

docs-html:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --all-features --open

coverage:
  cargo llvm-cov nextest

coverage-html:
  cargo llvm-cov nextest --html --open
