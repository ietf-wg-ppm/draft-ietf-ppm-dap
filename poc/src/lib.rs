//! Implementation of the replay logic introduced by [PR
//! #574](https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/574).
//!
//! The Helper role is implemented for tasks with the "leader_selected" batch mode.
//! ("time_interval" is similar.) The tests in this module illustrate different ways the Leader may
//! partition batches into aggregation jobs.

use std::{cmp::Ordering, collections::HashMap, ops::RangeInclusive};

// Basic types

pub type Time = u64; // seconds since UNIX epoch
pub type Duration = u64; // seconds
pub type BatchId = [u8; 16];
pub type ReportId = [u8; 16];
pub type Share = u64; // Actual type depends on the VDAF

// Task config

pub struct TaskConfig {
    pub time_precision: Duration,
}

impl TaskConfig {
    /// Return the time window for a report.
    pub fn time_window_for(&self, meta: &ReportMetadata) -> Time {
        meta.timestamp - (meta.timestamp % self.time_precision)
    }

    /// Partition the report shares in an aggregation into time windows and compute the report
    /// range for each window.
    pub fn time_span_for<'a>(
        &self,
        report_shares: &'a [ReportShare],
    ) -> HashMap<Time, (Vec<&'a ReportShare>, RangeInclusive<ReportMetadata>)> {
        let mut span = HashMap::<Time, Vec<&ReportShare>>::new();
        for report_share in report_shares {
            span.entry(self.time_window_for(&report_share.meta))
                .or_default()
                .push(report_share);
        }
        span.into_iter()
            .filter_map(|(time_window, report_shares)| {
                Some((
                    time_window,
                    match (
                        report_shares
                            .iter()
                            .map(|report_share| report_share.meta)
                            .min(),
                        report_shares
                            .iter()
                            .map(|report_share| report_share.meta)
                            .max(),
                    ) {
                        (Some(range_start), Some(range_end)) => {
                            (report_shares, range_start..=range_end)
                        }
                        _ => return None,
                    },
                ))
            })
            .collect()
    }
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            time_precision: 60 * 60, // one minute
        }
    }
}

// Reports

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportMetadata {
    pub id: ReportId,
    pub timestamp: Time,
}

impl PartialOrd for ReportMetadata {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReportMetadata {
    fn cmp(&self, other: &Self) -> Ordering {
        // A "report range" of a set of reports is determined by the first and last report ID in
        // lexicographic order.
        self.id.cmp(&other.id)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReportShare {
    pub meta: ReportMetadata,
    // NOTE We're abusing notation slightly here: In the draft, the "report share" refers to the
    // encrypted input share (an HPKE ciphertext), the public share, and so on. For the purposes of
    // our proof-of-concept, it's simpler to work with the plaintext input share.
    pub share: Share,
}

impl PartialOrd for ReportShare {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReportShare {
    fn cmp(&self, other: &Self) -> Ordering {
        self.meta.cmp(&other.meta)
    }
}

// Helper

/// The reported range for a time window.
///
/// This consists of a set of report ranges, each corresponding to an aggregation job.
#[derive(Debug, Default)]
struct ReportedRange(Vec<RangeInclusive<ReportMetadata>>);

impl ReportedRange {
    /// Add `range` to the reported range unless it overlaps with an existing range. Returns `true`
    /// if no overlap was detected and `false` otherwise.
    fn update(&mut self, range: RangeInclusive<ReportMetadata>) -> bool {
        let reported = &mut self.0;

        // Seek to the index of the first reported range that starts after `range`.
        let mut i = 0;
        while i < reported.len() {
            if range.end() < reported[i].start() {
                break;
            }
            i += 1;
        }

        // Insert `range` if it doesn't overlap with the previous range.
        if i == 0 || reported[i - 1].end() < range.start() {
            reported.insert(i, range);
            return true;
        }

        false
    }
}

#[derive(Default)]
pub struct Helper {
    task_config: TaskConfig,

    /// Reported ranges per time window.
    reported: HashMap<Time, ReportedRange>,

    /// Aggregate shares per batch, in "leader_selected" batch mode. In "time_interval" mode, we
    /// would split the aggregate share by time window.
    agg_share: HashMap<BatchId, Share>,
}

impl Helper {
    /// Handle an aggregation job from the Leader. Return the IDs of rejected reports.
    ///
    /// NOTE This is not a complete implementation of aggregation job handling. All that is
    /// implemented is the logic used to prevent replays across aggregation jobs. In particular,
    /// the Helper still needs to check for replays within each job.
    pub fn handle_agg_job(
        &mut self,
        report_shares: &[ReportShare],
        batch_id: &BatchId,
    ) -> Vec<ReportId> {
        let time_span = self.task_config.time_span_for(report_shares);
        let mut rejected = Vec::new();
        let mut agg_share = 0_u64;

        for (time_window, (report_shares, range)) in time_span {
            if self.reported.entry(time_window).or_default().update(range) {
                // We have successfully updated the reported range for the given time window, so
                // commit the aggregate share as well.
                //
                // NOTE While the replay check must be resolved before responding to the Leader, we
                // can wait until after the request to write out the aggregate share to storage.
                agg_share = report_shares
                    .iter()
                    .map(|r| r.share)
                    .fold(agg_share, |x, y| x.wrapping_add(y));
            } else {
                // The range overlaps with the reported range, so reject all reports in this range.
                //
                // NOTE It's possible for the Helper to make a smarter choice here that may result
                // in fewer rejected reports. Rather than reject the entire range, it can reject
                // the reports that fall in the intersection and update the reported range by
                // merging it with this one. We have opted for this simpler check in order to keep
                // the protocol text simple.
                for report_id in report_shares
                    .into_iter()
                    .map(|report_share| report_share.meta.id)
                {
                    rejected.push(report_id);
                }
            }
        }

        let agg_share_for_batch = self.agg_share.entry(*batch_id).or_default();
        *agg_share_for_batch = agg_share_for_batch.wrapping_add(agg_share);

        rejected
    }
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use super::*;
    use rand::prelude::*;

    /// Generate a report with the given timestamp and measurement.
    fn gen_report<R: Rng>(rng: &mut R, timestamp: Time, measurement: Share) -> [ReportShare; 2] {
        let meta = ReportMetadata {
            id: rng.gen(),
            timestamp,
        };
        let r = rng.gen();
        [
            ReportShare {
                meta,
                share: measurement.wrapping_sub(r),
            },
            ReportShare { meta, share: r },
        ]
    }

    // Leader strategies

    #[test]
    fn leader_strategy_sort_entire_batch() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        let mut reports = {
            repeat_with(|| {
                // Report timestamps span three time windows.
                let timestamp = rng.gen_range(0..helper.task_config.time_precision * 3);
                gen_report(&mut rng, timestamp, 1)
            })
            .take(1_000)
            .collect::<Vec<_>>()
        };

        let batch_id = rng.gen();

        // The Leader's aggregate share for the batch. Note that we're ignoring the details of VDAF
        // preparation in this test.
        let agg_share_0 = reports
            .iter()
            .map(|[report_share_0, _report_share_1]| report_share_0.share)
            .fold(0_u64, |x, y| x.wrapping_add(y));

        // The Helper's aggregate share for the batch.
        let agg_share_1 = {
            // The Leader is responsible for ensuring that, for each time window, the report ranges
            // of aggregation jobs are non-overlapping. The most straightforward way to ensure this
            // is to sort all reports in the batch and split it into chunks.
            //
            // NOTE A complete sort is not strictly necessary. Imagine you want to split the batch
            // into two aggregation jobs that are roughly equal in size. It's sufficient to just do
            // the first step of quicksort: find (or guess) the median report, then split the batch
            // into two sets, those that are smaller than or equal to the median and those that are
            // larger.
            reports.sort();

            let agg_jobs = {
                let mut agg_jobs = reports
                    .chunks(42)
                    .map(|reports_chunk| {
                        reports_chunk
                            .into_iter()
                            .map(|[_report_share_0, report_share_1]| report_share_1)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                // It doesn't matter what order the jobs are run processed in.
                agg_jobs.shuffle(&mut rng);
                agg_jobs
            };

            // Run aggregation jobs.
            for agg_job in agg_jobs {
                // Expect there to be no rejections.
                assert!(helper.handle_agg_job(&agg_job, &batch_id).is_empty());
            }

            helper.agg_share.get(&batch_id).cloned().unwrap()
        };

        // Expect a valid aggregate result.
        assert_eq!(1_000, agg_share_0.wrapping_add(agg_share_1));
    }

    #[test]
    fn leader_strategy_sort_each_time_window() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        let reports = {
            repeat_with(|| {
                let timestamp = rng.gen_range(0..helper.task_config.time_precision * 3);
                gen_report(&mut rng, timestamp, 1)
            })
            .take(1_000)
            .collect::<Vec<_>>()
        };

        let batch_id = rng.gen();

        let agg_share_0 = reports
            .iter()
            .map(|[report_share_0, _report_share_1]| report_share_0.share)
            .fold(0_u64, |x, y| x.wrapping_add(y));

        let agg_share_1 = {
            let report_shares = reports
                .into_iter()
                .map(|[_report_share_0, report_share_1]| report_share_1)
                .collect::<Vec<_>>();

            // Sorting the entire batch (as in `leader_strategy_sort_entire_batch()`) is expensive.
            // Instead, the Leader can buffer reports in each time window, then begin aggregating
            // once the time window elapses. Note that in practice it's important to wait a little
            // longer for stragglers to arrive.
            for (_time_window, (report_shares, _range)) in
                helper.task_config.time_span_for(&report_shares)
            {
                let mut report_shares = report_shares
                    .into_iter()
                    .map(Clone::clone)
                    .collect::<Vec<_>>();

                // The Leader still needs to ensure the aggregation jobs don't overlap, sort before
                // splitting into aggregation jobs.
                report_shares.sort();

                let agg_jobs = {
                    let mut agg_jobs = report_shares.chunks(42).collect::<Vec<_>>();

                    // Again, it doesn't matter what order the jobs are processed in.
                    agg_jobs.shuffle(&mut rng);
                    agg_jobs
                };

                for agg_job in agg_jobs {
                    // Expect there to be no rejections.
                    assert!(helper.handle_agg_job(agg_job, &batch_id).is_empty());
                }
            }

            helper.agg_share.get(&batch_id).cloned().unwrap()
        };

        assert_eq!(1_000, agg_share_0.wrapping_add(agg_share_1));
    }

    #[test]
    fn leader_strategy_split_time_window() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        let mut reports = {
            repeat_with(|| {
                let timestamp = 0;
                gen_report(&mut rng, timestamp, 1)
            })
            .take(1_000)
            .collect::<Vec<_>>()
        };

        // In some instances it may be useful for the Leader to be able to partition reports within
        // the same time window. Since the report ranges within the same time window must be
        // non-overlapping, it is necessary to buffer the entire time window then, split into
        // non-overlapping report ranges. Here we sort all of the reports, then split them into
        // batches of size at most 300.
        reports.sort();

        for batch in reports.chunks(300) {
            let batch_id = rng.gen();

            let agg_share_0 = batch
                .iter()
                .map(|[report_share_0, _report_share_1]| report_share_0.share)
                .fold(0_u64, |x, y| x.wrapping_add(y));

            let agg_share_1 = {
                let agg_jobs = {
                    let mut agg_jobs = batch
                        .chunks(42)
                        .map(|batch_chunk| {
                            batch_chunk
                                .into_iter()
                                .map(|[_report_share_0, report_share_1]| report_share_1)
                                .cloned()
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();

                    // It doesn't matter what order the jobs are run processed in.
                    agg_jobs.shuffle(&mut rng);
                    agg_jobs
                };

                // Run aggregation jobs.
                for agg_job in agg_jobs {
                    // Expect there to be no rejections.
                    assert!(helper.handle_agg_job(&agg_job, &batch_id).is_empty());
                }

                // Expect an aggregate share.
                assert!(helper.agg_share.get(&batch_id).is_some());
                helper.agg_share.get(&batch_id).cloned().unwrap()
            };

            // Expect a valid aggregate result.
            assert_eq!(batch.len() as Share, agg_share_0.wrapping_add(agg_share_1));
        }
    }

    // Rejection cases

    #[test]
    fn reject_replayed_range() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        let mut report_shares = repeat_with(|| gen_report(&mut rng, 0, 1))
            .map(|[_, report_share_1]| report_share_1)
            .take(5)
            .collect::<Vec<_>>();
        report_shares.sort();

        // To set up this test, we first aggregate a range of reports.
        let batch_id = rng.gen();
        assert!(helper
            .handle_agg_job(&report_shares[1..4], &batch_id)
            .is_empty());

        // Inner overlap: The range is contained by a reported range.
        assert_eq!(
            helper.handle_agg_job(&report_shares[1..2], &batch_id).len(),
            1
        );
        assert_eq!(
            helper.handle_agg_job(&report_shares[1..3], &batch_id).len(),
            2
        );
        assert_eq!(
            helper.handle_agg_job(&report_shares[1..4], &batch_id).len(),
            3
        );
        assert_eq!(
            helper.handle_agg_job(&report_shares[2..4], &batch_id).len(),
            2
        );
        assert_eq!(
            helper.handle_agg_job(&report_shares[3..4], &batch_id).len(),
            1
        );

        // Left overlap: The range contains the start of a reported range
        assert_eq!(
            helper.handle_agg_job(&report_shares[..4], &batch_id).len(),
            4
        );

        // Right overlap: The range contains the end of a reported range
        assert_eq!(
            helper.handle_agg_job(&report_shares[2..], &batch_id).len(),
            3
        );

        // Outer overlap: The range contains a reported range.
        assert_eq!(helper.handle_agg_job(&report_shares, &batch_id).len(), 5);
    }

    #[test]
    fn reject_replay_across_batches() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        let report_shares = {
            let [_, report_share_1] = gen_report(&mut rng, 0, 1);
            vec![report_share_1; 1]
        };

        assert!(helper.handle_agg_job(&report_shares, &rng.gen()).is_empty());

        // The Leader tries to assign a report to two batches.
        assert_eq!(helper.handle_agg_job(&report_shares, &rng.gen()).len(), 1);
    }

    // NOTE This test is intentionally flaky.
    #[test]
    fn reject_stragglers() {
        let mut rng = thread_rng();
        let mut helper = Helper::default();

        // To set up this test, aggregate a handful of reports that fall in the same time window.
        {
            let reports = {
                repeat_with(|| gen_report(&mut rng, 0, 1))
                    .take(100)
                    .collect::<Vec<_>>()
            };

            let report_shares = reports
                .into_iter()
                .map(|[_report_share_0, report_share_1]| report_share_1)
                .collect::<Vec<_>>();

            // Expect there to be no rejections.
            assert!(helper.handle_agg_job(&report_shares, &rng.gen()).is_empty());
        }

        println!("{:?}", helper.reported);

        // Try to aggregate a straggler, i.e., a report that falls in a time window that we've
        // already begun aggregating.
        {
            let [_, report_share] = gen_report(&mut rng, 0, 1);

            // Expect to reject the report. Even though we've only aggregated 100 reports, it's
            // highly likely (though not a certainty) that the straggler falls in the reported
            // range. Intuitively, because the report IDs are chosen at random, the more reports
            // we've aggregated, the larger the reported range.
            assert_eq!(1, helper.handle_agg_job(&[report_share], &rng.gen()).len());
        }
    }
}
