[![Crates.io](https://img.shields.io/crates/v/cfdp-rs)](https://crates.io/crates/cfdp-rs)
[![docs.rs](https://img.shields.io/docsrs/cfdp-rs)](https://docs.rs/cfdp-rs)
[![ci](https://github.com/us-irs/cfdp-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/us-irs/cfdp-rs/actions/workflows/ci.yml)
[![coverage](https://shields.io/endpoint?url=https://absatsw.irs.uni-stuttgart.de/projects/cfdp/coverage-rs/latest/coverage.json)](https://absatsw.irs.uni-stuttgart.de/projects/cfdp/coverage-rs/latest/index.html)

cfdp-rs - High level Rust crate for CFDP components
======================

The `cfdp-rs` Rust crate offers some high-level CCSDS File Delivery Protocol (CFDP) components to
perform file transfers according to the [CCSDS Blue Book 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf).
The underlying base packet library used to generate the packets to be sent is the
[spacepackets](https://egit.irs.uni-stuttgart.de/rust/spacepackets) library.

# Features

`cfdp-rs` supports various runtime environments and is also suitable for `no_std` environments.
It is recommended to activate the `alloc` feature at the very least to allow using the primary
components provided by this crate. These components will only allocate memory at initialization
time and thus are still viable for systems where run-time allocation is prohibited.

## Default features

 - [`std`](https://doc.rust-lang.org/std/): Enables functionality relying on the standard library.
 - [`alloc`](https://doc.rust-lang.org/alloc/): Enables features which require allocation support.
   Enabled by the `std` feature.

## Optional Features

 - [`serde`](https://serde.rs/): Adds `serde` support for most types by adding `Serialize` and `Deserialize` `derive`s
 - [`defmt`](https://defmt.ferrous-systems.com/): Add support for the `defmt` by adding the
   [`defmt::Format`](https://defmt.ferrous-systems.com/format) derive on many types.

# Examples

You can check the [documentation](https://docs.rs/cfdp-rs) of individual modules for various usage
examples.

# Coverage

Coverage was generated using [`grcov`](https://github.com/mozilla/grcov). If you have not done so
already, install the `llvm-tools-preview`:

```sh
rustup component add llvm-tools-preview
cargo install grcov --locked
```

After that, you can simply run `coverage.py` to test the project with coverage. You can optionally
supply the `--open` flag to open the coverage report in your webbrowser.
