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
- `wallet_session::WalletSession::truncate_to_height`: upstream's
  `WalletWrite::truncate_to_height` and the removal of the graft-buffer rows of the blocks
  it removed, in one transaction (`WalletDb::transactionally_with_extension`). It returns
  the height the wallet was truncated to. The scheduler's reorg recovery calls it.
- `persist::SparseFacade` and `persist::WriteBehindFacade` implement
  `WalletWrite::set_account_name`, the method `zcash_client_backend` adds to the trait.
  The sparse facade forwards it to the wallet db; the write-behind facade, which holds no
  connection, refuses it like every other write outside `put_blocks`.

### Changed
- `engine::ENGINE_BUILD` is `2026-10-20.v0.16-graft-buffer-fixes`.

### Fixed
- With graft on (`EngineConfig::graft_subtree`, the default), a Historic range resumed
  whatever the graft buffer held for its first shard, and a build lays rows out from the
  first row's position. Rows that did not end right before the range's start, as after an
  account import whose rescan starts inside an interrupted range's shard, put every later
  leaf of the commitment tree at the wrong position. A range now resumes only the run of
  rows that ends right before its start, on its own `from_state` frontier's leaf, and only
  when the commitment tree takes that run. The frontier's leaf vouches for the run's last
  row alone: a run with an earlier row that is not the chain's can conflict with the tree
  when it is built, and a range that resumed it would fail on every pass. So the seed
  first inserts the run into a copy of its shard as the wallet holds it, with the range's
  frontier inserted; nothing is written. A run that ends there on another leaf, such as
  another chain's rows a reorg's truncation can leave, or that the tree refuses, is not
  continued, and the range builds what it scans in that shard instead of buffering it next
  to the run, so neither the range's remainder nor the next pass's sweep takes the run up
  with the range's own rows. The next pass's sweep queues the run's blocks for a rescan
  and then deletes it (below), or keeps it, with a warning, when the wallet's block
  metadata cannot place its blocks; no seed resumes it. The resumed run is no longer
  deleted when the wallet already holds content for the shard (after a second committed
  unit of the interrupted range), which lost its leaves and anchors. A range also no
  longer deletes the rest of the shard's rows, rows of blocks that may stay scanned: its
  seed deletes only the rows at the positions it scans again, and a build or graft only
  the rows it built, so the others wait for the next pass's sweep (below).
- The range-end graft build, and every other build of buffered rows, inserted the rows
  without first registering their durable anchors as retained. With the wallet at its
  100-checkpoint budget (the ChainTip range's window), the build evicted the anchors it
  had just added, and the anchors it kept were never recorded as retained. Buffered rows
  also kept every per-block checkpoint when they were scanned deep below the chain tip,
  so a later build created checkpoints that graft off never creates. Graft on now leaves
  the same checkpoints and retained anchors as graft off.
- A pass stopped or aborted after a Historic range's last commit, such as a host abort
  that lands in the range's final drain, skipped the range-end build: the range's last
  shard stayed only in the graft buffer, so its leaves, checkpoints and durable anchors
  never reached the tree, and a later range that seeded in that shard deleted them. Each
  pass now starts with a sweep of the buffer for the runs no pending range will resume. A
  run is built when data the wallet already holds checks where it ends (the tree's leaf at
  its last position, or the stored server root of the shard it completes); any other run
  is deleted and its blocks are queued for a rescan. A wallet whose stranded rows are
  still buffered heals on its next pass. This change neither detects nor repairs what an
  earlier version already did: rows it deleted (their checkpoints and durable anchors are
  missing), or leaves it built at the wrong positions. A buffered row that will not decode
  no longer fails every pass: for each run of its shard, the sweep queues a rescan of the
  blocks holding it, by position, and then deletes it; a run the wallet's block metadata
  cannot place keeps its rows, with a warning. A range that still meets such a row seeds
  without the shard's rows and builds what it scans in that shard, with a warning. Only a
  row that will not decode counts: any other error reading the buffer (a busy database,
  an I/O error) fails the range for the pass, as before, and the sweep leaves that
  shard's rows as they are. Any other run the sweep cannot read, build or rescan gets a
  warning and keeps its rows; a sweep that fails only warns, and the pass goes on. A run
  whose end checks but whose build the tree refuses is deleted once its blocks are queued
  for a rescan, as any other.
- A reorg recovery's truncation and an account import's rewind left the graft-buffer rows
  of the blocks they queue again, though after a reorg those may be another chain's
  commitments. The truncation (`WalletSession::truncate_to_height`) and the engine's own
  account import (`WalletSession::import_account`) now drop every buffered row at or
  above their rewind point. The truncation drops them in upstream's own truncation
  transaction, so a crash or an error never leaves the wallet truncated with those rows
  still buffered; a pool whose tree size the highest remaining block does not record
  keeps its rows, with a warning. For an account a host imports into the wallet database
  itself, the first range to seed in the shard resumes only the run that ends right
  before its start, as above.

## [0.4.0-pre.2] - 2026-10-20

### Added
- `events::Progress::request_stop_for_wallet_change` and `Progress::stop_requested`. A
  host calls the first right before it changes the wallet (adding or removing an account,
  a rewind, a wipe), and the running session's scan ends at its next block instead of
  after the whole chunk. `Progress::begin_session` re-arms the stop, so a request never
  stops a later session.
- `block_source::StoppedForWalletChange` and `block_source::MemBlockSource::with_stop`,
  which make the in-memory block source refuse its next block once a stop is requested.
  The check is two relaxed atomic loads per block.
- `SlipstreamError::StoppedForWalletChange` and
  `SlipstreamError::is_stop_for_wallet_change`.
- `ffi_handle::StopReport`, `ffi_handle::SlipstreamHandle::{stop, stop_for_wallet_change,
  quiesce_before_start}`, `ffi_handle::{settle_passes, drain_wallet_writers}` and the
  `SlipstreamHandle::unfinished_passes` field: the bounded stop that proves the wallet
  file quiescent, which every host wrapper used to keep its own copy of. Its report says
  whether each wait finished and how long it took. A pass that outlives a stop's budget
  stays on record, so a later stop still answers for it.
- `ffi_handle::FfiSlipstreamStopReport`, the by-value C form of `StopReport` that the C
  ABI's two stop functions return: `settled` and `drained` as 1 or 0, `settle_ms` and
  `drain_ms` in milliseconds (`From<StopReport>`). The report return and
  `zcashlc_slipstream_stop_for_wallet_change` are the C ABI wrappers adopt with this
  release (today's wrappers return `bool` from `zcashlc_slipstream_stop`), and a wrapper's
  cbindgen re-declaration of the struct must keep its field order.

### Changed
- `block_source::MemBlockSource`'s `BlockSource::Error` is `StoppedForWalletChange` (was
  `Infallible`). A source built without `with_stop` never returns it.
- `session::run_session` returns when the host stops it for a wallet change, leaving
  `SyncState::Idle` and pushing no error event. It still never returns otherwise.
- Each `Progress::request_stop_for_wallet_change` owes, process-wide, a wait for the trial
  decryption the stopped scan leaves queued on rayon's global pool: the next scan in the
  process, on any handle (one reopened on the same wallet too), waits right before its
  first scan call until rayon has taken that backlog, so a stop that follows quickly is
  seen at the next block instead of after it. The wait overlaps the Tor bootstrap and the
  fetch of the first chunk, and one cut short by an abort leaves it owed.
- `ffi_handle::SlipstreamHandle` has a new public field, `unfinished_passes`: code that
  builds the handle with a struct literal must set it (to `Vec::new()`).
- `engine::ENGINE_BUILD` is `2026-10-20.v0.15-stop-for-wallet-change`.

## [0.4.0-pre.1] - 2026-10-06

### Changed
- Migrated to `zcash_address 0.14.0-pre.1`, `zcash_client_backend 0.25.0-pre.1`,
  `zcash_client_sqlite 0.23.0-pre.1`, `zcash_keys 0.17.0-pre.1`,
  `zcash_primitives 0.31.0-pre.1`, and `zcash_transparent 0.11.0-pre.1`.
- Unified addresses and unified full viewing keys are encoded at ZIP 316
  Revision 0 when Revision 0 can represent them: an address as `u…` and a UFVK
  as `uview…`; on testnet, as `utest…` and `uviewtest…`. An address whose only
  receiver is transparent, and a key or address carrying expiry metadata, are
  still encoded at Revision 2. Encodings stored by a host may differ from those
  this crate now produces; both revisions decode.
- `engine::ENGINE_BUILD` is `2026-10-06.v0.14-pre-1-crates`.

## [0.4.0-pre.0] - 2026-10-05

### Added
- `persist::SparseFacade` and `persist::WriteBehindFacade` implement
  `WalletWrite::queue_rescan`, which `zcash_client_backend` 0.25 adds.

### Changed
- Migrated to `incrementalmerkletree 0.9`, `orchard 0.16`, `rand 0.10`,
  `sapling-crypto 0.9`, `shardtree 0.8`, `zcash_address 0.14.0-pre.0`,
  `zcash_client_backend 0.25.0-pre.0`, `zcash_client_sqlite 0.23.0-pre.0`,
  `zcash_keys 0.17.0-pre.0`, `zcash_primitives 0.31.0-pre.0`,
  `zcash_protocol 0.11.0-pre.0`, `zcash_transparent 0.11.0-pre.0`, and
  `zip32 0.3`.
- The `gpu` feature requires `zodl-slipstream-gpuhash` 0.1.2, which is built on
  the same curve generation.
- Unified addresses and unified full viewing keys are encoded as ZIP 316
  Revision 2: an address as `zu…` when it has no transparent receiver and as
  `tu…` when it has one (its receivers come from the host's
  `UnifiedAddressRequest`), and a UFVK as `uvf…`; on testnet, as `zutest…`,
  `tutest…` and `uvftest…`. Encodings stored by a host differ from those this
  crate now produces.
- `engine::ENGINE_BUILD` is `2026-10-05.v0.13-nu7-pre-release-crates`.

## [0.3.0] - 2026-10-01

### Added
- `events`: `DownloadFailure`, `DOWNLOAD_FAILURE_STALL_STREAK`, `DOWNLOAD_FAILURE_RUN_GAP_SECS`,
  and the `Progress` methods `note_download_gave_up`, `note_blocks_released`,
  `note_pass_completed`, `begin_session`, `note_attempt_failed`, `download_failures`,
  `download_failure_secs` and `stall_secs`. They track, per block, a block download that keeps
  giving up, and derive from it the stall fact the snapshot reports as `stalled_seconds`.
- `grpc::SubtreeRoots::ironwood`, the server's Ironwood subtree roots, alongside `sapling` and
  `orchard`.
- `events`: the `Progress` methods `pass_start_permille`, `set_pass_start_permille`,
  `set_pass_start_permille_if_unset`, `scope_expanded`, `set_pass_baseline`, `pass_base_fetched`
  and `pass_base_scanned`. They record where a pass started, and the blocks it had fetched and
  scanned when the current suggest round began, which `progress_permille` measures from.

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
  reports the time since the first of them whenever that is longer, for as long as that block's
  latest give-up is at most ten minutes old. The count ends when a later download hands that
  block to the scanner, a pass completes, a new session starts, or a sync attempt — a pass, or
  the tip check between passes — fails without its download giving up, for example with no
  network. Give-ups are tracked per block, so failures at other blocks neither extend nor hide a
  run. A server that cannot deliver a block range therefore still reads as stalled even though
  every failed pass is retried, while a device that goes offline does not. A server whose passes
  only sometimes reach the download is reported later, or not at all, since each pass that fails
  before its download ends the count. A fetch that failed after delivering every block does not
  count.
- `grpc::get_subtree_roots`, `grpc::get_taddress_txids`, `grpc::get_address_utxos` and
  `transparent::refresh_utxos` take a new `progress: Option<&Progress>` argument, stamped for
  every message received.
- `grpc::SubtreeRoots` is `#[non_exhaustive]`, so a field for a future pool is not a breaking
  change.
- `progress_permille` climbs through a pass instead of holding at the session floor until the
  pass is nearly scanned. It maps the pass's downloaded and scanned blocks, at half weight each,
  into the gap between the position the pass started from and done. A scan-scope expansion (an
  import with an older birthday) re-bases it, a continuity repair counts only the blocks below
  its rewind height, and the wallet birthday is read again every suggest round. The session
  floor and `Done` reading 1000 are unchanged.
- `engine::ENGINE_BUILD` is `2026-09-24.v0.12-download-failure-stall`.

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
- Ironwood subtree roots are fetched from the server every pass and grafted like Sapling's and
  Orchard's, so Ironwood's shard indices stay a complete range. Previously they were only
  seeded locally: when one account's Ironwood tree was seeded near the tip before another
  account's older-birthday scan crossed Ironwood activation, the scan failed with
  `SubtreeDiscontinuity` and the sync retried forever.

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
