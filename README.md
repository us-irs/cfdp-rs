[![Crates.io](https://img.shields.io/crates/v/cfdp-rs)](https://crates.io/crates/cfdp-rs)
[![docs.rs](https://img.shields.io/docsrs/cfdp-rs)](https://docs.rs/cfdp-rs)
[![ci](https://github.com/us-irs/cfdp-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/us-irs/cfdp-rs/actions/workflows/ci.yml)
[![matrix chat](https://img.shields.io/matrix/sat-rs%3Amatrix.org)](https://matrix.to/#/#sat-rs:matrix.org)
<!-- Does not work right now, I'd need to host that myself. [![coverage](https://shields.io/endpoint?url=https://absatsw.irs.uni-stuttgart.de/projects/cfdp/coverage-rs/latest/coverage.json)](https://absatsw.irs.uni-stuttgart.de/projects/cfdp/coverage-rs/latest/index.html) -->

cfdp-rs - High level Rust crate for CFDP components
======================

The `cfdp-rs` Rust crate offers some high-level CCSDS File Delivery Protocol (CFDP) components to
perform file transfers according to the [CCSDS Blue Book 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf).
The underlying base packet library used to generate the packets to be sent is the
[spacepackets](https://egit.irs.uni-stuttgart.de/rust/spacepackets) library.

# Features

`cfdp-rs` currently supports following high-level features:

- Unacknowledged (class 1) file transfers for both source and destination side.
- Acknowledged (class 2) file transfers for both source and destination side.

The following features have not been implemented yet. PRs or notifications for demand are welcome!

- Suspending transfers
- Inactivity handling
- Start and end of transmission and reception opportunity handling
- Keep Alive and Prompt PDU handling

Check out the [documentation](https://docs.rs/cfdp-rs) for more information on available
Rust features.

# Examples

You can check the [documentation](https://docs.rs/cfdp-rs) of individual modules for various usage
examples.

# Coverage

Coverage can be generated using [`llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov). If you have not done so
already, install the tool:

```sh
cargo +stable install cargo-llvm-cov --locked
```

After this, you can run `cargo llvm-cov nextest` to run all the tests and display coverage.
