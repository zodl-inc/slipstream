// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL Slipstream.
//
// ZODL Slipstream is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL Slipstream is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! In-memory unit of transport: a height-ordered run of CompactBlocks plus
//! a byte-budgeted queue connecting fetch (producer) to scan (consumer).
//! Backpressure: permits are held until the CONSUMER drops the chunk's
//! `ChunkPermit`, so the budget covers queued AND in-processing bytes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use prost::Message;
use tokio::sync::{Semaphore, mpsc};
use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::error::SlipstreamError;

#[derive(Clone, Debug)]
pub struct Chunk {
    /// Index in the fetch plan (0-based, consecutive).
    pub index: u64,
    pub blocks: Vec<CompactBlock>,
    /// Sum of protobuf wire sizes. The in-memory footprint of decoded blocks
    /// can be 2–3× larger (Vec capacity, per-field allocations) — the budget
    /// is a conservative bound, not a tight one.
    pub estimated_bytes: usize,
    /// Trial-decryption work denominator: sapling outputs + orchard actions
    /// across all transactions in this chunk.
    pub outputs: u64,
    /// Work units: block weight + sum of all pool leaves (outputs + actions).
    pub work: u64,
}

impl Chunk {
    pub fn from_blocks(index: u64, blocks: Vec<CompactBlock>) -> Self {
        let estimated_bytes = blocks.iter().map(Message::encoded_len).sum();
        // Count total sapling outputs and orchard actions across all transactions.
        let outputs: u64 = blocks
            .iter()
            .flat_map(|block| &block.vtx)
            .map(|tx| (tx.outputs.len() + tx.actions.len()) as u64)
            .sum();
        // Work units: block weight + all pool leaves.
        let work: u64 = blocks.iter().map(crate::work::block_work).sum();
        Self {
            index,
            blocks,
            estimated_bytes,
            outputs,
            work,
        }
    }

    pub fn start_height(&self) -> Option<u64> {
        self.blocks.first().map(|b| b.height)
    }
    pub fn end_height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.height)
    }

    /// Appends `next`, the chunk that directly follows this one (its first block is
    /// this one's last + 1); returns `next` back when it does not.
    pub fn append(&mut self, next: Chunk) -> Result<(), Chunk> {
        match (self.end_height(), next.start_height()) {
            (Some(end), Some(start)) if start == end + 1 => {
                self.estimated_bytes += next.estimated_bytes;
                self.outputs += next.outputs;
                self.work += next.work;
                self.blocks.extend(next.blocks);
                Ok(())
            }
            _ => Err(next),
        }
    }
}

/// Holds the byte-budget permits for one chunk; drop to release budget.
#[must_use = "dropping the permit releases the byte budget; hold it until the chunk is fully processed"]
pub struct ChunkPermit {
    _permits: tokio::sync::OwnedSemaphorePermit,
    /// Permits of chunks merged into this one ([`ChunkPermit::absorb`]).
    merged: Vec<tokio::sync::OwnedSemaphorePermit>,
}

impl ChunkPermit {
    /// Holds `other`'s budget too, until this permit is dropped.
    pub fn absorb(&mut self, other: ChunkPermit) {
        self.merged.push(other._permits);
        self.merged.extend(other.merged);
    }
}

/// v0.5 pacer fix: the boundary-treestate fetch spawned WHEN THE CHUNK IS
/// EMITTED, so its RTT overlaps queue wait + scan + submit instead of racing
/// one scan call (the P1 split measured that overhang at 62 % of the Mac
/// scan wall on a slow-treestate day).
pub type BoundaryHandle = tokio::task::JoinHandle<
    Result<zcash_client_backend::proto::service::TreeState, SlipstreamError>,
>;

/// One queue item: the chunk, its share of the byte budget, and its boundary fetch.
pub type QueuedChunk = (Chunk, ChunkPermit, Option<BoundaryHandle>);

/// Injected at queue construction (scheduler): given a chunk's end height,
/// spawn its boundary treestate fetch, or return `None` when the scan will not
/// need that state (the range's last block, in server mode). Without a fetcher
/// (tests, darkside) the scan side spawns the fetches it needs itself.
pub type BoundaryFetcher = Arc<dyn Fn(u64) -> Option<BoundaryHandle> + Send + Sync>;

pub struct ChunkQueueSender {
    tx: mpsc::UnboundedSender<QueuedChunk>,
    budget: Arc<Semaphore>,
    budget_bytes: usize,
    boundary_fetcher: Option<BoundaryFetcher>,
    meter: Arc<QueueMeter>,
}

pub struct ChunkQueueReceiver {
    rx: mpsc::UnboundedReceiver<QueuedChunk>,
    meter: Arc<QueueMeter>,
}

/// What the fetch side can see of its consumer through one queue: how long the
/// scanner has waited in [`ChunkQueueReceiver::recv`] for its next chunk, and how
/// many blocks and estimated bytes were sent. The fetch's adaptive prefetch
/// (`fetch::FetchBoost`) reads it to tell a fetch-bound scan (the scanner waits)
/// from a scan-bound one (the queue is full and it never waits).
#[derive(Debug)]
pub struct QueueMeter {
    base: std::time::Instant,
    /// (completed waits, start of the wait in progress or `None`), microseconds
    /// since `base`; one lock so a sample is a consistent snapshot.
    waits: std::sync::Mutex<(u64, Option<u64>)>,
    sent_blocks: AtomicU64,
    sent_bytes: AtomicU64,
}

impl QueueMeter {
    fn new() -> Self {
        Self {
            base: std::time::Instant::now(),
            waits: std::sync::Mutex::new((0, None)),
            sent_blocks: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
        }
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    /// Total time the consumer has waited for a chunk, the wait in progress included.
    /// A consistent snapshot: a wait ending meanwhile is counted once.
    pub fn scan_waited(&self) -> std::time::Duration {
        // `now` is read under the lock too, so a wait ending right after this
        // snapshot ends at or after it: samples never run ahead of later ones.
        let waits = self.waits.lock().unwrap_or_else(|e| e.into_inner());
        let ongoing = waits
            .1
            .map_or(0, |since| self.now_us().saturating_sub(since));
        std::time::Duration::from_micros(waits.0.saturating_add(ongoing))
    }

    /// Starts a wait; returns its start for [`Self::end_wait`].
    fn begin_wait(&self) -> u64 {
        let since = self.now_us();
        self.waits.lock().unwrap_or_else(|e| e.into_inner()).1 = Some(since);
        since
    }

    /// Ends the wait that started at `since`: moves it from in progress to the
    /// completed total in one step.
    fn end_wait(&self, since: u64) {
        let mut waits = self.waits.lock().unwrap_or_else(|e| e.into_inner());
        let waited = self.now_us().saturating_sub(since);
        waits.0 = waits.0.saturating_add(waited);
        waits.1 = None;
    }

    /// `(blocks, estimated bytes)` sent into the queue so far.
    pub fn sent(&self) -> (u64, u64) {
        (
            self.sent_blocks.load(Ordering::Relaxed),
            self.sent_bytes.load(Ordering::Relaxed),
        )
    }
}

/// Ends a wait on the meter when `recv` returns or its future is dropped.
struct WaitGuard<'a> {
    meter: &'a QueueMeter,
    since: u64,
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.meter.end_wait(self.since);
    }
}

/// `budget_bytes` bounds the estimated bytes in flight (queued + being
/// consumed). A single chunk larger than the budget is clamped to the whole
/// budget rather than deadlocking.
pub fn chunk_queue(budget_bytes: usize) -> (ChunkQueueSender, ChunkQueueReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    let meter = Arc::new(QueueMeter::new());
    (
        // A zero budget degenerates to 1 byte (fully serial) instead of blocking forever.
        ChunkQueueSender {
            tx,
            budget: Arc::new(Semaphore::new(budget_bytes.max(1))),
            budget_bytes: budget_bytes.max(1),
            boundary_fetcher: None,
            meter: Arc::clone(&meter),
        },
        ChunkQueueReceiver { rx, meter },
    )
}

impl ChunkQueueSender {
    /// Install the boundary-treestate fetcher (scheduler, production path).
    pub fn set_boundary_fetcher(&mut self, f: BoundaryFetcher) {
        self.boundary_fetcher = Some(f);
    }

    /// The queue's [`QueueMeter`], shared with the receiver.
    pub fn meter(&self) -> Arc<QueueMeter> {
        Arc::clone(&self.meter)
    }

    /// Waits until the byte budget admits the chunk, then enqueues it.
    pub async fn send(&self, chunk: Chunk) -> Result<(), SlipstreamError> {
        // v0.5: fire the boundary fetch BEFORE the budget wait — treestates
        // are immutable historical data, and the earlier the RTT starts the
        // more scan it hides under. At most (queued chunks + 1) fetches are
        // ever in flight, so a slow server sees a trickle, never a burst.
        let boundary = match (&self.boundary_fetcher, chunk.end_height()) {
            (Some(f), Some(end)) => f(end),
            _ => None,
        };
        // Saturate: budgets beyond u32::MAX simply cap the per-chunk acquisition;
        // the semaphore itself holds the full usize budget, so backpressure stays correct.
        let need =
            u32::try_from(chunk.estimated_bytes.min(self.budget_bytes).max(1)).unwrap_or(u32::MAX);
        let permits = self
            .budget
            .clone()
            .acquire_many_owned(need)
            .await
            .map_err(|_| SlipstreamError::Stopped)?;
        let (blocks, bytes) = (chunk.blocks.len() as u64, chunk.estimated_bytes as u64);
        self.tx
            .send((
                chunk,
                ChunkPermit {
                    _permits: permits,
                    merged: Vec::new(),
                },
                boundary,
            ))
            .map_err(|_| SlipstreamError::Stopped)?;
        self.meter.sent_blocks.fetch_add(blocks, Ordering::Relaxed);
        self.meter.sent_bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }
}

impl ChunkQueueReceiver {
    /// The next chunk if one is queued right now, without waiting.
    pub fn try_recv(&mut self) -> Option<QueuedChunk> {
        self.rx.try_recv().ok()
    }

    /// The next chunk; `None` when all senders are dropped (fetch finished or
    /// aborted). The time spent waiting
    /// here is recorded on the queue's [`QueueMeter`].
    pub async fn recv(&mut self) -> Option<QueuedChunk> {
        if let Ok(item) = self.rx.try_recv() {
            return Some(item);
        }
        let since = self.meter.begin_wait();
        let _guard = WaitGuard {
            meter: &self.meter,
            since,
        };
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zcash_client_backend::proto::compact_formats::{
        CompactOrchardAction, CompactSaplingOutput, CompactTx,
    };

    fn block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            hash: vec![height as u8; 32],
            ..Default::default()
        }
    }

    fn chunk_of(index: u64, heights: std::ops::RangeInclusive<u64>) -> Chunk {
        Chunk::from_blocks(index, heights.map(block).collect())
    }

    /// Helper to construct a CompactTx with known outputs and actions.
    fn tx_with_outputs_and_actions(outputs: u32, actions: u32) -> CompactTx {
        CompactTx {
            outputs: (0..outputs)
                .map(|_| CompactSaplingOutput::default())
                .collect(),
            actions: (0..actions)
                .map(|_| CompactOrchardAction::default())
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn estimated_bytes_counts_encoded_blocks() {
        let c = chunk_of(0, 1..=10);
        assert!(
            c.estimated_bytes > 10 * 32,
            "must at least cover the hashes"
        );
        assert_eq!(c.start_height(), Some(1));
        assert_eq!(c.end_height(), Some(10));
    }

    #[tokio::test]
    async fn queue_blocks_producer_when_budget_exhausted() {
        let c1 = chunk_of(0, 1..=10);
        let budget = c1.estimated_bytes + 1; // fits exactly one chunk
        let (tx, mut rx) = chunk_queue(budget);

        tx.send(c1).await.expect("first send fits");

        let c2 = chunk_of(1, 11..=20);
        let second = tx.send(c2);
        // Budget exhausted -> second send must be pending until we consume.
        tokio::select! {
            _ = second => panic!("second send must block while budget is held"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }

        // Consume + drop the first chunk's permit -> budget freed.
        let (got, permit, _boundary) = rx.recv().await.expect("first chunk");
        assert_eq!(got.index, 0);
        drop(permit);

        let c2 = chunk_of(1, 11..=20);
        tokio::time::timeout(Duration::from_secs(1), tx.send(c2))
            .await
            .expect("send unblocks after consumer releases budget")
            .expect("send ok");
    }

    #[tokio::test]
    async fn oversized_chunk_clamps_instead_of_deadlocking() {
        let big = chunk_of(0, 1..=100);
        let (tx, mut rx) = chunk_queue(8); // budget far below one chunk
        tokio::time::timeout(Duration::from_secs(1), tx.send(big))
            .await
            .expect("clamped send completes")
            .expect("send ok");
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn recv_returns_none_when_sender_dropped() {
        let (tx, mut rx) = chunk_queue(1024);
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn zero_budget_degenerates_to_serial_not_deadlock() {
        let (tx, mut rx) = chunk_queue(0);
        tokio::time::timeout(Duration::from_secs(1), tx.send(chunk_of(0, 1..=3)))
            .await
            .expect("send completes under zero budget")
            .expect("send ok");
        assert!(rx.recv().await.is_some());
    }

    /// A boundary fetcher may decline a boundary; that chunk then carries no fetch.
    #[tokio::test]
    async fn boundary_fetcher_may_decline_a_boundary() {
        let (mut tx, mut rx) = chunk_queue(1 << 20);
        tx.set_boundary_fetcher(Arc::new(|end: u64| -> Option<BoundaryHandle> {
            (end < 20).then(|| {
                tokio::spawn(async move {
                    Err(SlipstreamError::Transport(format!("test fetch at {end}")))
                })
            })
        }));
        tx.send(chunk_of(0, 1..=10)).await.expect("send");
        tx.send(chunk_of(1, 11..=20)).await.expect("send");
        let (_, _first_permit, first) = rx.recv().await.expect("first chunk");
        assert!(first.is_some(), "a boundary below the range end is fetched");
        let (_, _last_permit, last) = rx.recv().await.expect("last chunk");
        assert!(last.is_none(), "the declined boundary carries no fetch");
    }

    #[test]
    fn chunk_outputs_counts_vtx_outputs_and_actions() {
        // Build two blocks with known vtx contents.
        let blocks = vec![
            CompactBlock {
                height: 1,
                hash: vec![1; 32],
                vtx: vec![
                    tx_with_outputs_and_actions(3, 2), // 3 outputs + 2 actions = 5
                    tx_with_outputs_and_actions(1, 0), // 1 output + 0 actions = 1
                ],
                ..Default::default()
            },
            CompactBlock {
                height: 2,
                hash: vec![2; 32],
                vtx: vec![
                    tx_with_outputs_and_actions(0, 4), // 0 outputs + 4 actions = 4
                ],
                ..Default::default()
            },
        ];
        // Expected: 5 + 1 + 4 = 10
        let chunk = Chunk::from_blocks(0, blocks);
        assert_eq!(
            chunk.outputs, 10,
            "outputs must sum sapling outputs + orchard actions"
        );
    }

    #[tokio::test]
    async fn meter_counts_the_consumers_wait_and_what_was_sent() {
        let (tx, mut rx) = chunk_queue(1 << 20);
        let meter = tx.meter();
        assert_eq!(meter.scan_waited(), Duration::ZERO);
        assert_eq!(meter.sent(), (0, 0));

        // A chunk already queued is taken without waiting.
        let c = chunk_of(0, 1..=10);
        let bytes = c.estimated_bytes as u64;
        tx.send(c).await.expect("send");
        assert_eq!(meter.sent(), (10, bytes));
        let _first = rx.recv().await.expect("first");
        assert_eq!(meter.scan_waited(), Duration::ZERO);

        // A wait in progress counts before it ends, and once.
        let waiter = tokio::spawn(async move {
            let got = rx.recv().await.map(|(c, _, _)| c.index);
            (got, rx)
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        let ongoing = meter.scan_waited();
        assert!(
            ongoing >= Duration::from_millis(50),
            "ongoing wait {ongoing:?}"
        );
        tx.send(chunk_of(1, 11..=12)).await.expect("send");
        let (got, mut rx) = waiter.await.expect("join");
        assert_eq!(got, Some(1));
        let done = meter.scan_waited();
        assert!(done >= ongoing && done < Duration::from_secs(5), "{done:?}");

        // A dropped recv future ends its wait.
        let dropped = tokio::time::timeout(Duration::from_millis(30), rx.recv()).await;
        assert!(dropped.is_err());
        let after = meter.scan_waited();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            meter.scan_waited(),
            after,
            "no wait is in progress any more"
        );
    }

    /// A wait that ends while the booster samples is counted once: samples are
    /// consistent snapshots, so one never runs ahead of a later one (counting a
    /// wait both in progress and completed would).
    #[test]
    fn a_wait_ending_during_a_sample_is_never_counted_twice() {
        let meter = Arc::new(QueueMeter::new());
        let waiter = {
            let meter = Arc::clone(&meter);
            std::thread::spawn(move || {
                for _ in 0..20_000 {
                    let since = meter.begin_wait();
                    let spin = std::time::Instant::now();
                    while spin.elapsed() < Duration::from_micros(20) {
                        std::hint::spin_loop();
                    }
                    meter.end_wait(since);
                }
            })
        };
        let mut last = Duration::ZERO;
        while !waiter.is_finished() {
            let now = meter.scan_waited();
            assert!(
                now >= last,
                "sample {now:?} after {last:?}: a wait was counted twice"
            );
            last = now;
        }
        waiter.join().expect("waiter");
        assert!(meter.scan_waited() >= last);
    }
}
