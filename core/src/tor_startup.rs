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

//! Retained status and cancellation for one opt-in Tor startup generation.

use std::future::Future;
use tokio::sync::watch;
use tokio::time::Instant;

/// A startup's phase. Every phase except `Starting` is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorStartupPhase {
    Starting,
    Ready,
    Failed,
    TimedOut,
    Cancelled,
}

/// Retained state for exactly one immutable generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TorStartupSnapshot {
    pub generation: u64,
    pub phase: TorStartupPhase,
}

/// Cancellation and observation capability for one startup attempt.
///
/// The host supplies the absolute monotonic deadline shared with its other
/// startup work. Clones observe the same retained state; use a new control for
/// every generation. Cancellation affects unfinished startup only: once Ready,
/// the existing session abort/pass-lock contract owns the session's lifetime.
#[derive(Clone, Debug)]
pub struct TorStartupControl {
    deadline: Instant,
    state: watch::Sender<TorStartupSnapshot>,
}

impl TorStartupControl {
    pub fn new(generation: u64, deadline: Instant) -> Self {
        let (state, _) = watch::channel(TorStartupSnapshot {
            generation,
            phase: TorStartupPhase::Starting,
        });
        Self { deadline, state }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn snapshot(&self) -> TorStartupSnapshot {
        *self.state.borrow()
    }

    /// Publish cancellation synchronously, including before the worker is polled.
    pub fn cancel(&self) {
        self.finish(TorStartupPhase::Cancelled);
    }

    /// Observe terminal state even when its notification preceded this call.
    pub async fn wait_for_terminal(&self) -> TorStartupSnapshot {
        let mut receiver = self.state.subscribe();
        loop {
            let snapshot = *receiver.borrow_and_update();
            if snapshot.phase != TorStartupPhase::Starting {
                return snapshot;
            }
            // This method borrows the sender, so it cannot close while waiting.
            receiver
                .changed()
                .await
                .expect("startup sender is retained");
        }
    }

    fn finish(&self, phase: TorStartupPhase) -> TorStartupSnapshot {
        self.state.send_if_modified(|snapshot| {
            if snapshot.phase == TorStartupPhase::Starting {
                snapshot.phase = match phase {
                    TorStartupPhase::Ready | TorStartupPhase::Failed
                        if Instant::now() >= self.deadline =>
                    {
                        TorStartupPhase::TimedOut
                    }
                    _ => phase,
                };
                true
            } else {
                false
            }
        });
        self.snapshot()
    }

    /// Bound the entire admission/bootstrap future, never resetting its budget.
    /// The drop guard exists before polling so aborting a queued worker retains
    /// Cancelled even if it has never run. Completion cannot replace a terminal.
    pub(crate) fn run<F, T, E>(&self, future: F) -> impl Future<Output = Result<T, TorStartupPhase>>
    where
        F: Future<Output = Result<T, E>>,
    {
        let guard = self.cancel_on_drop();
        async move {
            let _guard = guard;
            tokio::select! {
                biased;
                snapshot = self.wait_for_terminal() => Err(snapshot.phase),
                _ = tokio::time::sleep_until(self.deadline) => {
                    Err(self.finish(TorStartupPhase::TimedOut).phase)
                }
                result = future => match result {
                    Ok(value) => {
                        let phase = self.finish(TorStartupPhase::Ready).phase;
                        if phase == TorStartupPhase::Ready {
                            Ok(value)
                        } else {
                            Err(phase)
                        }
                    }
                    Err(_) => Err(self.finish(TorStartupPhase::Failed).phase),
                },
            }
        }
    }

    pub(crate) fn cancel_on_drop(&self) -> StartupDropGuard {
        StartupDropGuard(self.clone())
    }
}

pub(crate) struct StartupDropGuard(TorStartupControl);

impl Drop for StartupDropGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    #[tokio::test(start_paused = true)]
    async fn tor_startup_budget_includes_queue_and_retries() {
        let start = Instant::now();
        let control = TorStartupControl::new(7, start + Duration::from_secs(60));
        let result = control
            .run(async {
                // Admission consumed 40 seconds of the same 60-second budget.
                tokio::time::sleep(Duration::from_secs(40)).await;
                // Bootstrap failed; its retry backoff cannot get a fresh budget.
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok::<_, ()>(())
            })
            .await;
        assert_eq!(result, Err(TorStartupPhase::TimedOut));
        assert_eq!(Instant::now() - start, Duration::from_secs(60));
        assert_eq!(
            control.snapshot(),
            TorStartupSnapshot {
                generation: 7,
                phase: TorStartupPhase::TimedOut
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tor_startup_cancel_interrupts_pending_bootstrap() {
        let control = TorStartupControl::new(8, Instant::now() + Duration::from_secs(60));
        let worker_control = control.clone();
        let worker = tokio::spawn(async move {
            worker_control
                .run(std::future::pending::<Result<(), ()>>())
                .await
        });
        tokio::task::yield_now().await;
        control.cancel();
        assert_eq!(worker.await.unwrap(), Err(TorStartupPhase::Cancelled));
        assert_eq!(control.snapshot().phase, TorStartupPhase::Cancelled);
    }

    #[tokio::test]
    async fn tor_startup_terminal_survives_lost_wakeup() {
        let control = TorStartupControl::new(9, Instant::now() + Duration::from_secs(60));
        // No waiter exists when completion publishes its notification.
        assert_eq!(
            control.run(async { Err::<(), _>(()) }).await,
            Err(TorStartupPhase::Failed)
        );
        let snapshot =
            tokio::time::timeout(Duration::from_millis(100), control.wait_for_terminal())
                .await
                .unwrap();
        assert_eq!(
            snapshot,
            TorStartupSnapshot {
                generation: 9,
                phase: TorStartupPhase::Failed
            }
        );
    }

    #[tokio::test]
    async fn tor_startup_old_completion_cannot_overwrite_new_generation() {
        let old = TorStartupControl::new(10, Instant::now() + Duration::from_secs(60));
        let new = TorStartupControl::new(11, Instant::now() + Duration::from_secs(60));
        old.cancel();
        assert_eq!(new.run(async { Ok::<_, ()>(()) }).await, Ok(()));
        assert_eq!(
            old.run(async { Ok::<_, ()>(()) }).await,
            Err(TorStartupPhase::Cancelled)
        );
        assert_eq!(
            new.snapshot(),
            TorStartupSnapshot {
                generation: 11,
                phase: TorStartupPhase::Ready
            }
        );
        assert_eq!(old.snapshot().phase, TorStartupPhase::Cancelled);
    }

    #[tokio::test]
    async fn tor_startup_dropped_worker_retains_cancelled() {
        let control = TorStartupControl::new(12, Instant::now() + Duration::from_secs(60));
        let future = control.run(std::future::pending::<Result<(), ()>>());
        // Even a never-polled worker must publish cancellation when discarded.
        drop(future);
        assert_eq!(control.snapshot().phase, TorStartupPhase::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn tor_startup_error_completion_after_deadline_is_timed_out() {
        let control = TorStartupControl::new(13, Instant::now() + Duration::from_secs(60));
        tokio::time::advance(Duration::from_secs(61)).await;
        // A future may complete its poll after spending the remaining budget in
        // synchronous setup. Its error must not replace the deadline outcome.
        assert_eq!(
            control.finish(TorStartupPhase::Failed).phase,
            TorStartupPhase::TimedOut
        );
    }
}
