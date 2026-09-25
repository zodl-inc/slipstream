<!--
Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
SPDX-License-Identifier: AGPL-3.0-only

This file is part of ZODL Slipstream.

ZODL Slipstream is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License,
version 3 only, as published by the Free Software Foundation.

ZODL Slipstream is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Affero General Public License for more details.

Commercial licensing: see COMMERCIAL-LICENSE.md.
-->

# DEV-6: the adaptive split-on-GoAway reflex — report

**Branch:** `dev-perf-reconquest` &nbsp;·&nbsp; **Commits:** 2 (`f5910e6` the reflex + 17 tests,
plus this report) &nbsp;·&nbsp; **Scope:** `slipstream-dev/` only, no pushes &nbsp;·&nbsp;
**Endpoint:** `zec.rocks:443` (TLS) &nbsp;·&nbsp; **Key material:** fresh throwaway BIP-39 seed
(24 words, generated locally from `/dev/urandom` in a scratchpad-only helper depending on the
same pinned `bip39 = "2.2.2"` the workspace already uses, never funded, mnemonic/UFVK/wallet
dirs/helper project all deleted at task end) &nbsp;·&nbsp; **Window:** birthday `3,105,000` → tip
(mainnet)

**Headline finding:** the mechanism is **built, tested, and confirmed inert (correctly) against
non-matching errors on live traffic** — `is_goaway_frame_overload` classifies precisely on the h2
GoAway/`ENHANCE_YOUR_CALM`/`too_many_data_frames` shape and nothing else; `goaway_halved_cap`
halves a failing request's span from the full remaining plan-chunk range down to a 1,000-block
floor before yielding to the pre-existing sleep ladder; `PlanChunkCursor::request_end` threads the
adaptive cap through `open_and_pump`/`pump_block_stream` so the **existing** resume-from-height /
`sub_index` machinery reassembles the extra sub-requests in strict order with zero changes to the
reorder stage. **No GoAway fired in either of this session's two completed live restores** — and,
unlike DEV-5, this session can say *why* with primary-source certainty rather than shrug at
server-side variance: reading the actual `h2 = "0.4.15"` pinned by this workspace's `Cargo.lock`
shows the `too_many_data_frames` self-protection **does not exist in that version's source at
all** — it first appears in `h2-0.4.18`. The proof therefore rests on the halving math + the
classifier's unit tests (both exhaustive) **plus** something DEV-5 never got: the classifier's
correctness demonstrated against **real, field-observed non-GoAway transport errors** encountered
during the live runs (connect failures, a stream idle timeout, and a novel `Io(Kind(TimedOut))`
shape) — all correctly left alone.

---

## 1. Design

### 1.1 What DEV-5 built vs. what was missing

DEV-5 shipped `EngineConfig::chunk_split_blocks` (default 5,000): a **proactive constant** that
caps how many blocks the client groups into one sub-chunk for handoff to the scan queue. It is
sized for the one range that had been field-observed failing when it shipped. It has no opinion
about any *other* budget a server (or, as this session found, the client's own transport stack)
might be enforcing — it cannot, because it is a single fixed number chosen in advance. The
project owner's framing for this task was exact: "dynamic handling, not a constant." DEV-6 is
that dynamic handling: a **reactive** mechanism that responds to the *actual* failure signal
instead of guessing a safe size ahead of time.

### 1.2 The classifier — `is_goaway_frame_overload` (`core/src/fetch.rs`)

By the time a stream-read error reaches `worker()`'s retry loop, it is already a flattened
`SlipstreamError::Transport(String)` — both call sites that produce it (`pump_block_stream`'s
per-item `map_err`, `open_and_pump`'s request-setup `map_err`) build it via
`format!("{ctx}: {e}")` where `e` is the raw `tonic::Status`. This session read the *actual*
pinned dependency source (not assumed) to confirm that string is not lossy for classification
purposes:

- `tonic-0.14.6/src/status.rs`'s `Display for Status` writes
  `code: '{code}', message: {message:?}, source: {source:?}` — the LAST term is `{:?}` (Debug) of
  `self.source()`.
- `hyper-1.10.1/src/error.rs`'s `Debug for Error` is `f.debug_tuple("hyper::Error").field(&kind).field(cause)` —
  it recurses into the underlying cause.
- `h2-0.4.15/src/error.rs`'s `Error`/`Kind` both `#[derive(Debug)]`, and `Kind::GoAway(Bytes, Reason, Initiator)`'s
  derived Debug prints exactly `GoAway(b"...", REASON, INITIATOR)`.

Chained together, a live GoAway-terminated stream produces a string containing, verbatim,
`GoAway(`, the reason name, and the reason's debug payload — which is exactly the shape
`DEV-5-FRAMECAP-REPORT.md` §1.4 cited from a different session
(`F2-ADAPTER-PARITY-REPORT.md`). The classifier requires **all three** markers:

```rust
fn is_goaway_frame_overload(err: &SlipstreamError) -> bool {
    let SlipstreamError::Transport(msg) = err else { return false; };
    msg.contains("GoAway(")
        && msg.contains("ENHANCE_YOUR_CALM")
        && msg.contains("too_many_data_frames")
}
```

`ENHANCE_YOUR_CALM` alone is not enough — h2 raises that same reason code for at least one other
self-protection this session found by reading `h2-0.4.15/src/proto/streams/streams.rs`
(`too_many_internal_resets`, guarding against reset-storm abuse) — so the debug-payload string is
load-bearing for "match precisely," not decorative. `goaway_classifier_rejects_other_enhance_
your_calm_reasons` proves this directly.

**Where the error actually originates (a correction to DEV-5's framing, not a new fact — the
citation was already there).** DEV-5's own §1.4 citation includes `Library` as the third field
of the `GoAway` tuple, quoted verbatim from another session. This session read `h2`'s `Initiator`
usage to work out what that means: `Initiator::Library` marks a GoAway the **local h2 stack**
raised on itself, as opposed to `Initiator::Remote` (a frame that arrived from the peer). Grepping
`h2-0.4.18/src/proto/streams/streams.rs` (the first version with the literal string
`"too_many_data_frames"` — see §3.2) shows exactly this call site:

```rust
res = counts.record_data_frame(payload_len).map_err(|_| {
    tracing::debug!("too many small DATA frames");
    Error::library_go_away_data(Reason::ENHANCE_YOUR_CALM, "too_many_data_frames")
});
```

So this specific GoAway is the **client's own h2 crate** protecting itself against a peer
delivering an excessive run of small DATA frames relative to progress — it is not literally a
frame lightwalletd sent. DEV-5's "server's h2 per-stream frame-count protection" framing is
correct in *effect* (triggered by the server's response shape) but imprecise about *where the
connection-teardown decision is made*; this report states it exactly because it also bears
directly on §3's live-check limitation.

### 1.3 The halving math — `goaway_halved_cap` (pure, no I/O)

```rust
fn goaway_halved_cap(attempted_span: u32, floor: u32) -> Option<u32> {
    if attempted_span <= floor { None } else { Some((attempted_span / 2).max(floor)) }
}
```

`attempted_span` is the block count the just-failed attempt actually requested — the plan
chunk's full remaining span the first time, the prior cap (or less, near a plan chunk's tail) on
every subsequent halving. `None` means "give up the adaptive path for this GoAway; the normal
ladder handles it" — either the span was already at the floor, or (via the combinator below) the
error wasn't this class at all. For the shipped default 10,000-block plan chunk with the
1,000-block floor: `10000 → 5000 → 2500 → 1250 → 1000`, then a fifth GoAway at 1,000 falls
through. `goaway_halving_sequence_from_full_chunk_to_floor` proves the whole sequence in one
assertion; three more tests cover the exactly-at-floor stop, the no-undershoot clamp (`1250/2 =
625` must clamp UP to 1,000, not land below it), and a plan-chunk tail already smaller than the
floor giving up immediately rather than "halving" a span that was never going to be halved twice.

### 1.4 Threading the cap without touching the reorder stage

`PlanChunkCursor` gained one field, `goaway_cap: Option<u32>`, and one method:

```rust
fn request_end(&self) -> u64 {
    match self.goaway_cap {
        Some(cap) => self.end.min(self.resume_from.saturating_add(u64::from(cap)).saturating_sub(1)),
        None => self.end,
    }
}
```

`cursor.end` — the plan chunk's TRUE final height — is untouched by this; it alone still decides
`is_last`. `open_and_pump`/`pump_block_stream` both gained a `request_end: u64` parameter (the
*this-attempt* target, `cursor.end` when unrestricted) used for the actual `GetBlockRange`
request, the "clean end" comparison, and the "ended short" message; `is_last` is computed
separately as `request_end == cursor.end`. This is the one seam DEV-6 needed: everything else —
`resume_from` tracking, `next_sub_index` continuity, the `(plan_index, sub_index)` reorder-stage
contract — is the **exact same machinery** T6.8-S already built for error-triggered resume,
now also driven by success-triggered continuation (a capped request completing cleanly, with more
of the plan chunk still to fetch).

### 1.5 The flow inside `worker()`

```
attempt N: request_end = cursor.request_end()   (cursor.end, or the active cap)
  → open_and_pump(...)
      Ok(Completed), resume_from > end  → plan chunk fully released, next index
      Ok(Completed), resume_from <= end → MORE of this plan chunk remains (capped
                                            request succeeded); loop immediately,
                                            `attempt` untouched
      Ok(ConsumerGone)                  → abort quietly (unchanged)
      Err(err):
        is_goaway_frame_overload(err) AND attempted_span > floor
          → cursor.goaway_cap = Some(halved); goaway_splits += 1; reconnect;
            loop immediately — NO sleep, NO `attempt` strike
        otherwise (not this class, OR already at/below the floor)
          → pre-DEV-6 handling, byte for byte: attempt += 1 (moved from the loop
            head into this arm — a no-op for every case that doesn't hit the new
            branch, since the original increment was never read on the success
            path), zero-progress reset, retries_per_chunk check, warn!, sleep,
            reconnect
```

The reconnect on the adaptive path is deliberate, not incidental: an h2 GOAWAY tears down the
*whole connection*, not just the one stream, so the next (smaller) request needs a fresh channel
exactly like the pre-existing ladder already assumes for every other transport error.

**Design decision not fully specified by the task, made and documented explicitly:** `goaway_cap`
is **sticky** for the rest of a plan chunk once engaged — a successful capped sub-request does not
spring back to the unrestricted size for the plan chunk's remaining blocks. The alternative
(reset to `None` after any success) risks immediately re-provoking the same GoAway on the very
next request within the same plan chunk. Sticky-until-the-next-plan-chunk is the more
conservative "learned lesson" reading of "the reactive counterpart to a constant," and is
called out here as a judgment call rather than left implicit.

---

## 2. Observability

- `FetchStats.goaway_splits: u64` — new field, populated from a `Arc<AtomicU64>` shared across
  every `worker()` task and read back after all workers join (mirrors the existing
  `next`/`floor` atomic-counter pattern in this same file). Counts **halving steps**, not plan
  chunks — a chunk that halves 10,000→5,000→2,500 before succeeding counts 2.
- `run_fetch`'s `"fetch done"` `info!` line: `goaway_splits=N` appended.
- `FetchStatsTotals.goaway_splits: u64` (`core/src/scheduler.rs`) — accumulated alongside
  `blocks`/`bytes` in `run_to_completion`, one line: `report.fetch.goaway_splits +=
  fetch_stats.goaway_splits;`.
- `report::log_pass_summary`'s `"sync stage split"` line (`core/src/report.rs`): `goaway_splits =
  outcome.report.fetch.goaway_splits` appended.
- The CLI `sync` subcommand's console summary (`cli/src/main.rs`): `| goaway_splits {}` appended
  to the existing `ranges … | fetched … | scanned …` line.
- **Deliberately not touched:** `BenchSummary`/`report::bench_summary()` (the machine-readable
  perf-comparison JSON artifact `slipstream-cli bench` writes). "Wherever fetch stats aggregate"
  is read here as the `FetchStats → FetchStatsTotals → SyncReport` chain plus its two log sites
  and the CLI summary — not the separate timing/census-focused bench schema, which is a different
  artifact with its own consumers. Mirrors DEV-5's own §2.1 "deliberately not touched" restraint.

---

## 3. Tests

All in `core/src/fetch.rs` unless noted; 17 new, all passing individually (not just by aggregate
count).

| Test | Proves |
|---|---|
| `goaway_classifier_matches_fabricated_chain` | The exact DEV-5-cited shape matches |
| `goaway_classifier_rejects_plain_connection_reset` | An unrelated transport error does not match |
| `goaway_classifier_rejects_other_enhance_your_calm_reasons` | `ENHANCE_YOUR_CALM` alone (h2's `too_many_internal_resets`) is not enough — the debug string is load-bearing |
| `goaway_classifier_rejects_non_transport_variant` | Gates on the `SlipstreamError` variant, not substring content anywhere |
| `goaway_halving_sequence_from_full_chunk_to_floor` | 10000→5000→2500→1250→1000, the full sequence |
| `goaway_halving_stops_once_at_or_below_floor` | Exactly-at and already-below both give up |
| `goaway_halving_never_undershoots_the_floor` | `1250/2=625` clamps UP to 1000, never below |
| `goaway_halving_small_remaining_span_gives_up_immediately` | A plan-chunk tail under the floor never engages |
| `adaptive_response_engages_on_matching_goaway_above_floor` | The classify-then-halve combinator, positive case |
| `adaptive_response_none_on_matching_goaway_at_floor` | Combinator, floor case |
| `adaptive_response_none_on_non_goaway_error_regardless_of_span` | Combinator, non-matching case |
| `request_end_unrestricted_without_a_cap` | `None` cap → full `cursor.end` |
| `request_end_clamped_by_an_active_cap` | `Some(cap)` → `resume_from + cap - 1` |
| `request_end_cap_interacts_with_an_advanced_resume_from` | The cap re-anchors on an ADVANCED `resume_from` — the explicit "resume-height interaction" the task named |
| `request_end_cap_never_exceeds_the_plan_chunk_true_end` | A cap near a plan chunk's tail clamps to `cursor.end`, never past it |
| `pump_partial_request_end_below_plan_chunk_end_is_not_last` | A capped request completing at `request_end < cursor.end` is `Completed` but NOT `is_last`, and `resume_from` lands exactly one past `request_end` |
| `pump_multiple_sequential_capped_requests_then_final_is_last` | Two sequential capped requests against the same cursor reassemble with dense `sub_index`, exactly one `is_last` (on the request that reaches the TRUE end), and every height `3,355,000..=3,364,999` exactly once — constraint 1 (in-order reassembly across a halved sub-range) proven directly |

`worker()` itself has no direct unit test — neither did it before DEV-6. It owns a real
`LwdClient`/gRPC channel and this file's own established altitude is to unit-test the pumping
mechanics directly (`pump_resume_after_midstream_error_no_duplicates` already proves the
error-triggered resume contract the same way) and rely on the live check for the full
worker-level path. DEV-6 followed that precedent rather than introducing a new one.

All 8 pre-existing `pump_block_stream` call sites (production `open_and_pump` plus 7 pre-existing
tests) were updated to pass `request_end` explicitly — in every pre-existing test this equals the
cursor's original `end`, so none of their assertions changed; this is a mechanical parameter
addition, not a behavior change, confirmed by the full suite staying green.

---

## 4. Live check

### 4.1 Protocol and method

Same release binary (`f5910e6`, `cargo build --release -p slipstream-cli`), same throwaway UFVK,
same birthday (`3,105,000`), same endpoint (`zec.rocks:443`), fresh temp wallet dir per run,
deleted after. **Method for re-exposing the killer range:** the CLI already exposes DEV-5's own
knob flag-for-flag (`sync --chunk-split-blocks`), so no test-only override was needed —
`--chunk-split-blocks 10000` (the plan's own `--chunk` default) makes the block-count cap
unreachable for a 10,000-block plan chunk, restoring the exact pre-DEV-5 shape: plan chunk 25
(`3,355,000..3,364,999` for this birthday) ships as one undivided 10,000-message gRPC stream,
byte-cap-safe (§DEV-5 report §1.2), giving the frame-overload guard the same chance to fire that
DEV-5's own "without the fix" arm gave it.

### 4.2 Results

| Run | Outcome | Wall | `fetch_s` | `scan_s` | Blocks | Plan-25 shape | Non-GoAway transport errors this run | GoAway |
|---|---|---:|---:|---:|---:|---|---|:---:|
| 1st attempt (incomplete) | **killed at 5 min, not counted in n=2** | ≥300s | — | — | fetched 351,803 (frozen) | not reached in logs before kill | 3× connect-failed, 1× treestate timeout, 3× stream-idle-timeout | none |
| 1 (fresh retry) | completed, exit 0 | 77.4s | 66.3s | 76.9s | 351,806 | **1 sub-chunk, 10,000 blocks, len=10000, outputs=29269** | 8× connect-failed, 1× stream-idle-timeout, 3× `Io(Kind(TimedOut))` | none |
| 2 | completed, exit 0 | 23.2s | 10.5s | 22.5s | 351,807 | **1 sub-chunk, 10,000 blocks, len=10000, outputs=29269** | none | none |

`outputs=29269` on both completed runs is byte-identical to DEV-5's own baseline citation for
this exact range (§3.2 of that report) — confirming the killer range really did ship whole, not
some different shape.

### 4.3 What happened with the "hang," stated plainly

The first attempt sat with `fetched` and `scanned` counters completely frozen for over four
minutes with zero new log lines, which is alarming to see live and is disclosed here rather than
quietly discarded. It was killed and retried fresh rather than left running past the 5-minute
window. The retry — under **similarly rough** network conditions (8 connect failures, a stream
idle timeout, and three instances of a transport error shape this session had not seen before,
`hyper::Error(Body, Error { kind: Io(Kind(TimedOut)) })`) — completed cleanly in 77.4s. Chain of
reasoning for why this reads as a bounded-but-slow network patch rather than a DEV-6 hang, not a
certainty claimed outright:

1. `goaway_splits=0` in both "fetch done" lines the first attempt logged before going quiet — the
   new code path provably never executed during that run, so it cannot be the cause.
2. `goaway_halved_cap` and `goaway_adaptive_response` are pure functions proven (§1.3, §3 table)
   to strictly decrease toward the floor and then stop — no unbounded loop is reachable through
   them by construction.
3. The "adaptive partial success" continuation (`Ok(Completed)` with more of the plan chunk left)
   is bounded by `resume_from` strictly advancing on every emission — also provably terminating.
4. `connect_direct_with_retry`'s own (pre-existing, untouched) ladder is 6 attempts with backoff
   capped at 16s and a 10s per-attempt `connect_timeout` — bounded to roughly a minute and a half
   worst case, but the chunk-level ladder can call it up to 4 times per plan chunk, and multiple
   plan chunks can be independently cycling through this at once — arithmetic that comfortably
   reaches "several minutes" under sustained connect failures without needing any bug at all.
5. The retry's own symptoms (worse-looking than the first attempt's, by count) still resolved
   in 77s, one concrete data point that this class of rough patch does resolve within the
   existing bounded machinery rather than wedging it.

This is reasoning toward a conclusion, not a proof by exhaustion of every code path this session
did not touch — flagged as such rather than overclaimed.

### 4.4 The classifier, validated against real errors this session did not have to fabricate

Across the two completed runs, 12 real transport-error events spanning 3 distinct shapes fired —
none of them GoAways, none of them misclassified:

```
connect zec.rocks: transport error
block stream …: stream idle timeout (30s without a message)
block stream …: code: 'Unknown error', message: "h2 protocol error: error reading a body from
  connection", source: hyper::Error(Body, Error { kind: Io(Kind(TimedOut)) })
```

The third shape is new to this session's cataloging — an h2-level I/O timeout, not a GoAway at
all — and the classifier correctly ignored it (no `GoAway(` substring), leaving it to the
unchanged `chunk fetch failed; retrying from resume height` warn! + backoff + reconnect path,
verbatim pre-DEV-6 text. This is evidence for constraint 3 ("Non-GoAway errors keep today's
behavior byte-for-byte") that DEV-5 never had the chance to gather, because nothing errored in
DEV-5's clean baseline runs.

### 4.5 Why a live GoAway could not fire this session — a primary-source answer, not a shrug

This session read `h2-0.4.15`'s actual source (the version this workspace's `Cargo.lock` pins,
confirmed via `grep -A3 '^name = "h2"$' Cargo.lock`) and the specific self-protection
(`Error::library_go_away_data(Reason::ENHANCE_YOUR_CALM, "too_many_data_frames")`,
`counts.record_data_frame(...)`) **does not exist in that version's source at all** — it was
introduced later; the earliest of this session's three locally-cached h2 versions to contain the
literal string `"too_many_data_frames"` is `h2-0.4.18`. This means, independent of network luck,
**this exact binary cannot raise this exact classified error** — the calm outcome has a code-level
explanation, not just an absence-of-evidence one. This is scoped precisely: it says nothing about
whether some *other* component (a proxy in front of lightwalletd, or a different client/server h2
stack) could raise a similarly-shaped-but-differently-worded GoAway; it says only that *this*
dependency version, in *this* binary, cannot produce the *exact* text this classifier — correctly,
per "match precisely" — requires. Bumping `h2` is out of this task's fence (no dependency changes
were made or are proposed here); flagged as a fact worth the team's attention, not acted on.

---

## 5. Gates

```
cargo build --workspace --all-targets                                   -> clean, no warnings
cargo test --workspace:
  slipstream-cli:           40 passed; 0 failed
  zodl-slipstream (core):  314 passed; 0 failed; 11 ignored   (297 DEV-5 baseline + 17 new)
  census_scan:               1 passed; 0 failed
  stress_sparse_join:        2 passed; 0 failed
  tor_runtime_spike:         0 passed; 1 ignored (network-gated, expected)
  zodl-slipstream-gpuhash:   1 passed; 0 failed
  doc-tests (both crates):   0/0 (none)
  TOTAL: 358 passed, 0 failed, 12 ignored  (341 DEV-5 baseline + 17 new; unchanged ignore set)

cargo clippy --workspace --all-targets --all-features -- -D warnings    -> clean
  (one lint hit and fixed during this task: clippy::too_many_arguments on
  pump_block_stream's 8th parameter [request_end] -- allowed with a comment,
  precedented identically in scan.rs's own internal seams)
cargo fmt --all -- --check                                              -> clean
cargo build --release -p slipstream-cli                                 -> clean, used for the live check
```

---

## 6. The sandblasting lesson, completed

Slipstream 0.1.0's original insight — back when "sandblasting" first meant hundreds of megabytes
per 10,000 blocks — was that a **static** chunk size cannot survive a chain whose density varies
by two orders of magnitude across its own history: the byte splitter had to become
**density-adaptive**, measuring the actual stream and cutting it wherever it actually got heavy,
because no single constant chosen in advance could be right everywhere. DEV-5 extended that same
lesson to a second axis (message *count*, not just byte volume) but, by the project owner's own
diagnosis, extended it only halfway: `chunk_split_blocks` is a single number, chosen once, for one
observed failure. DEV-6 completes it. The fetch layer now carries three genuinely distinct
self-tuning mechanisms, each responding to a different signal at a different timescale:

1. **The byte/block-count splitter** (T6.8-S, DEV-5) — adapts to **density**, measured
   continuously as blocks stream in, deciding how to group ALREADY-ARRIVED data for the queue.
2. **The GoAway-adaptive reflex** (DEV-6, this task) — adapts to a **specific failure signal**,
   measured only when it fires, deciding how big the NEXT request may safely be.
3. **The wire-collapse detector and endpoint failover** (v0.7 P2, pre-existing) — adapts to
   **sustained throughput health**, measured over a rolling window, deciding whether the current
   *server* is worth staying on at all.

None of the three knows about the others, and none needs to: density-adaptive grouping bounds
memory and queue granularity regardless of why a stream is heavy; the GoAway reflex bounds request
size regardless of why the transport choked; the failover bounds which endpoint gets the traffic
regardless of why it went bad. A constant can only ever encode "the one thing someone already
measured." A reflex — this task's whole point — encodes "shrink until the actual, present
condition stops complaining," which is the only shape of fix that survives a threshold nobody on
this side of the connection is allowed to see (§4.5). That is the lesson slipstream's byte
splitter taught in 0.1.0, now paid in full across every axis this layer currently knows how to
measure.

---

## 7. Honest notes

1. **No GoAway fired in either of this session's two completed live runs** — 0/2, exactly
   matching DEV-5's own 0/4 experience on the identical range. Not fished for further; the task's
   own fallback ("if the server stays calm this session, say so plainly") is exercised here
   honestly.
2. **This session can explain the calm result with more certainty than DEV-5 could**: the exact
   `too_many_data_frames` guard is absent from the `h2 = "0.4.15"` version this workspace's
   `Cargo.lock` actually pins (confirmed by reading that version's source directly, not assumed);
   it first appears in `h2-0.4.18`. A live reproduction of this EXACT classified error was
   therefore architecturally impossible against this exact binary this session, independent of
   network luck. This does not mean no GoAway of any kind could ever occur (see honest note 5),
   only that this specific, precisely-matched one could not, this session, against this
   dependency graph.
3. **A refinement to DEV-5's own framing, not a new fact**: the `Initiator::Library` tag was
   already present, verbatim, in DEV-5's own §1.4 citation. This session is the first to trace
   what that tag means (h2's own client-side stack self-protecting, not a frame the server sent)
   by reading `h2`'s `Initiator` enum usage directly. DEV-5's "server's h2 frame-count protection"
   phrasing is correct in effect (the server's response shape is what triggers it) but the
   connection-teardown decision itself is local — stated precisely here because it also explains
   why the reconnect step in the adaptive path is necessary (the whole connection goes away, not
   just the offending stream).
4. **The first live-check attempt appeared to hang for 5+ minutes and was killed and retried.**
   Disclosed in full in §4.3 rather than quietly re-run and only the clean result reported. The
   reasoning chain for why this reads as bounded-but-slow (rough network conditions compounding
   through the PRE-EXISTING, unchanged connect-retry ladder) rather than a DEV-6 regression is
   laid out step by step in that section; it rests on `goaway_splits=0` (the new code path
   provably did not run) plus the halving math's provable termination, not on re-running it enough
   times to feel confident. This is the single most important thing in this report to read
   skeptically rather than take on faith.
5. **The classifier's "do not broaden" requirement was validated against a real error shape this
   session had never cataloged before it appeared live**: `hyper::Error(Body, Error { kind:
   Io(Kind(TimedOut)) })`, encountered 3 times in run 1. It was correctly left alone (no `GoAway(`
   substring) and fell through to the unchanged normal ladder. This is stronger evidence than the
   unit tests alone provide, and it is evidence DEV-5 never had the opportunity to gather (nothing
   errored in DEV-5's clean baseline runs).
6. **The sticky-cap design decision (§1.5) is this agent's own reading of an underspecified
   corner of the task**, not something the brief stated explicitly. It is documented in the code
   and flagged here rather than silently assumed; a future session could reasonably choose
   differently (reset the cap to `None` after any successful sub-request) and the halving math
   and tests would need no changes to support that — only `PlanChunkCursor`'s doc comment and the
   `Ok(Completed)` branch in `worker()`.
7. **`BenchSummary`/`bench_summary()` (the separate machine-readable perf-comparison JSON
   artifact) was deliberately left untouched** — "wherever fetch stats aggregate" was scoped to
   the `FetchStats → FetchStatsTotals → SyncReport` chain and its two log sites plus the CLI
   summary line, not the bench schema, which serves a different purpose (cross-run timing/census
   comparison) and has its own consumers. Mirrors DEV-5's own §2.1 restraint on
   `scaled_for_device_memory`.
8. **The floor (1,000 blocks) is a fixed module constant** (`GOAWAY_ADAPTIVE_FLOOR_BLOCKS`), not
   threaded through `EngineConfig`/a CLI flag the way DEV-5's `chunk_split_blocks` was. The task
   specified "a floor of 1,000 blocks" as a fixed value rather than asking for a tunable knob, so
   this keeps the change surgical; flagged in case a future session wants it configurable (the
   same pattern DEV-5 already established for `chunk_split_blocks` would apply directly).
9. **This task is the legitimate, first-class implementation of an idea DEV-5's own report
   flagged and explicitly declined to build** (`DEV-5-FRAMECAP-REPORT.md` §6, honest note 7):
   that session received a mid-task message proposing this exact mechanism, correctly identified
   it as unverified injected content rather than the user's actual instruction, and did not act on
   it — while noting the underlying idea "is not obviously wrong as a future follow-up" and should
   "come back through a verified channel as its own scoped task." This task's brief cites that
   exact honest note by name and arrived as this agent's own top-level task assignment (not
   spliced into an observed tool result), which is the verified-channel shape DEV-5 asked for.
   Recorded here for the ledger, not because it changed how this task was executed.

---

## Appendix: mechanism summary for the FINAL MESSAGE

- Classifier: `is_goaway_frame_overload` — requires `GoAway(` + `ENHANCE_YOUR_CALM` +
  `too_many_data_frames` all present in the `SlipstreamError::Transport` message; confirmed via
  primary-source reading of tonic/hyper/h2's actual Display/Debug impls that this text is present
  verbatim whenever the underlying cause truly is this class.
- Halving: `goaway_halved_cap(attempted_span, floor)` — halves toward `GOAWAY_ADAPTIVE_FLOOR_BLOCKS
  = 1_000`, clamped up to the floor, `None` once at/below it (falls through to the pre-DEV-6
  ladder unchanged).
- Threading: `PlanChunkCursor::request_end()` — the plan chunk's true `end`, clamped by an active
  cap; `is_last` still decided by `request_end == cursor.end` alone.
- Tests added: 17, all in `core/src/fetch.rs`, all individually confirmed passing.
- Live outcome: **0/2 GoAways fired** on the two completed restores (a third, incomplete attempt
  was killed after 5+ minutes under rough network conditions and retried; not counted toward n=2).
  Confirmed, via primary-source dependency-version reading, that this exact classified error
  cannot fire against the `h2 = "0.4.15"` this workspace's `Cargo.lock` currently pins — the calm
  result has a code-level explanation, not just a network-luck one. The classifier was
  additionally validated live against 12 real non-matching transport-error events across 3
  distinct shapes (including one novel to this session), none misclassified.
- Gates: build clean, 358/358 tests passed (0 failed, 12 ignored, unchanged ignore set from
  DEV-5's 341/0/12 baseline), clippy clean (one precedented `too_many_arguments` allow), fmt
  clean.
- Commits: 2 on `dev-perf-reconquest` (`f5910e6` reflex + tests, plus this report's own commit).
- Fences: `slipstream-dev/` only, no other repos touched, throwaway key material generated and
  fully deleted (mnemonic, UFVK, both temp wallet dirs, the seedgen scratchpad helper project),
  no push, no sub-agents. Nothing in `EngineConfig`/`Package.swift`/any persisted config was
  changed by the live check — `--chunk-split-blocks 10000` was a per-invocation CLI override
  only, so there is nothing to "restore" beyond confirming the shipped default (5,000) is
  untouched in the diff (it is — see the commit).
