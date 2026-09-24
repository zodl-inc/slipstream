# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

### Added
- `events`: `DownloadFailure`, `DOWNLOAD_FAILURE_STALL_STREAK`, `DOWNLOAD_FAILURE_RUN_GAP_SECS`,
  and the `Progress` methods `note_download_gave_up`, `note_blocks_released`,
  `note_pass_completed`, `begin_session`, `download_failures`, `download_failure_secs` and
  `stall_secs`. They track, per block, a block download that keeps giving up, and derive from it
  the stall fact the snapshot reports as `stalled_seconds`.

### Changed
- `stalled_seconds` (and `Progress::last_progress_unix`) now also move whenever data arrives from
  the server during a pass — every streamed block and every metadata message (a subtree root, an
  address-history transaction, a UTXO), direct or over Tor — not only when a counter moves. A slow
  but working pass no longer reads as stalled, so hosts that restart stalled passes stop
  restarting healthy ones.
- Completing a write-behind persist unit and building the range-end tree now also count as
  forward progress for `stalled_seconds`, so a long local-only tail (a slow device finishing a
  range) no longer reads as stalled.
- `stalled_seconds` also counts a block download that keeps failing at the same block: once the
  download has given up twice at one block, with no more than ten minutes between give-ups, it
  reports the time since the first of them whenever that is longer, until a later download hands
  that block to the scanner, a pass completes, or a new session starts. Give-ups are tracked per
  block, so failures at other blocks neither extend nor hide a run. A server that cannot deliver a
  block range therefore still reads as stalled even though every failed pass is retried. Passes
  that fail before their download starts, for example with no network, do not count, nor does a
  fetch that failed after delivering every block.
- `grpc::get_subtree_roots`, `grpc::get_taddress_txids`, `grpc::get_address_utxos` and
  `transparent::refresh_utxos` take a new `progress: Option<&Progress>` argument, stamped for
  every message received.

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
