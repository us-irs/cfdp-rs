Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

- Bumped `spacepackets` to v0.18

## Fixed

- Destination handler's `TransactionParams::reset` now resets all fields instead of just two.
  The incomplete reset left stale acknowledged-mode state behind, so a new transaction's Metadata
  PDU was mistaken for a duplicate of an already-processed one and silently dropped, breaking
  every transfer after the first one on a given destination handler instance.
- Source handler's `TransactionParams::reset` had the same issue. A second transaction on the
  same source handler instance could compute its EOF checksum over stale state left behind by the
  first one.
- Metadata-only transactions (e.g. a Proxy Put Request per CCSDS 727.0-B-5 6.1) now correctly
  send and expect an EOF (No error) PDU, as required by 4.6.1.1.9 case (C). The source handler no
  longer tries to checksum a source file that does not exist for this case, and the destination
  handler no longer tries to create or truncate a destination file that was never named.
- Destination handler no longer panics when a metadata PDU's Message To User TLVs overflow its
  internal buffer. It now returns `DestError::MsgsToUserBufferTooSmall` instead, and the buffer
  was bumped from 1024 to 2048 bytes.

# [v0.3.0] 2025-09-25

- Bumped `spacepackets` to v0.16
- Bumped `defmt` to v1

## Added

- Acknowledged mode support for both source and destination handler.
- `FaultInfo` structure which is passed to user fault callbacks.

# [v0.2.0] 2024-11-26

- Bumped `thiserror` to v2
- Bumped `spacepackets` to v0.13
- The source and destination handlers can now be used without the `std` feature and only require
  the `alloc` feature.

# [v0.1.0] 2024-09-11

Initial release

[unreleased]: https://egit.irs.uni-stuttgart.de/rust/cfdp/compare/v0.3.0...HEAD
[v0.3.0]: https://egit.irs.uni-stuttgart.de/rust/cfdp/compare/v0.2.0...v0.3.0
[v0.2.0]: https://egit.irs.uni-stuttgart.de/rust/cfdp/compare/v0.1.0...v0.2.0
