# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

### Changed
- `stalled_seconds` (and `Progress::last_progress_unix`) now also move whenever data arrives from
  the server during a pass — every streamed block and every successful metadata response, direct
  or over Tor — not only when a counter moves. A slow but working pass no longer reads as stalled,
  so hosts that restart stalled passes stop restarting healthy ones.

### Fixed
- A fetch whose plan chunk exhausts its retry budget now fails the pass immediately, so the
  pass-level retry takes over (or, when wire failover is armed, the engine fails over to an
  alternate endpoint at once). Previously the other workers kept running and could wait behind
  the missing chunk indefinitely, leaving the pass in `Syncing` with no progress.
- A slow block stream no longer fails its attempt and re-downloads its sub-chunk when
  `chunk_timeout` elapses: the blocks received so far are handed on as a shorter sub-chunk and
  the stream continues. When a stream errors, goes silent, or ends early, the blocks it already
  delivered are handed on before the attempt is retried, so the retry resumes after them instead
  of downloading them again.

## [0.2.0] - 2026-08-19

### Changed
- Updated to `zcash_client_backend-0.24`, `zcash_client_sqlite-0.22` final releases.
  The 0.1.x release series was published against release candidate versions of these
  crates.

## [0.1.1] - 2026-08-07

Initial public release of the `zodl-slipstream` crate. This crate provides an
optimized syncing engine for Zcash wallets. It is licensed under the GNU Affero
General Public License, version 3 only (AGPL-3.0-only). Commercial licensing is
available from Znewco, Inc. - see COMMERCIAL-LICENSE.md for details.

## [0.1.0] - 2026-08-07 [YANKED]

Published without the `LICENSE`, `COMMERCIAL-LICENSE.md`, and
`LICENSE-EXCEPTIONS.md` files that this crate's source headers reference.
Superseded by 0.1.1.
