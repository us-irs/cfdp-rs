Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

# [v0.3.0] 2025-09-??

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
