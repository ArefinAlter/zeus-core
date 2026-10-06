//! Interval sets over byte offsets: the committed ranges of a job (03 section 3.4).
//!
//! A [`RangeSet`] is kept in **normal form** (invariant I4): sorted, disjoint and non-adjacent
//! half-open intervals, so a clean sequential download is one interval. `insert` is idempotent and
//! monotone; `remove` exists only for invalidation (03 section 7.6) and splits intervals as needed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeus_types::{ByteRange, TypesError};

/// A set of byte offsets stored as normalised half-open intervals.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<ByteRange>", into = "Vec<ByteRange>")]
pub struct RangeSet {
    /// start -> end, with `start < end`, no overlap, and `end < next start` (non-adjacent).
    map: BTreeMap<u64, u64>,
}

impl std::fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(self.map.iter().map(|(s, e)| format!("[{s}, {e})")))
            .finish()
    }
}

/// A violation of the normal form found by [`RangeSet::check_normal_form`] (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NormalFormError {
    /// An interval is empty or inverted.
    #[error("empty or inverted interval starting at {start}")]
    EmptyInterval {
        /// Start of the offending interval.
        start: u64,
    },
    /// Two intervals overlap or touch.
    #[error("intervals at {first_start} and {second_start} overlap or touch")]
    NotDisjoint {
        /// Start of the earlier interval.
        first_start: u64,
        /// Start of the later interval.
        second_start: u64,
    },
    /// An interval extends beyond the known total size.
    #[error("interval ending at {end} exceeds the total {total}")]
    BeyondTotal {
        /// End of the offending interval.
        end: u64,
        /// The total size.
        total: u64,
    },
}

impl RangeSet {
    /// The empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from arbitrary (possibly overlapping, unsorted) ranges, normalising them. This is
    /// the repair path of recovery step 5 (03 section 10).
    pub fn from_ranges(ranges: impl IntoIterator<Item = ByteRange>) -> Self {
        let mut set = Self::new();
        for r in ranges {
            set.insert(r);
        }
        set
    }

    /// Adds `[start, end)` and returns how many bytes were **newly** covered (0 when the interval
    /// was already covered, which makes the operation idempotent).
    pub fn insert(&mut self, range: ByteRange) -> u64 {
        if range.is_empty() {
            return 0;
        }
        let (mut start, mut end) = (range.start, range.end);
        let mut already_covered = 0u64;
        let mut absorbed = Vec::new();
        // Begin at the interval that starts at or before `start`: it may touch or contain it.
        let from = self
            .map
            .range(..=start)
            .next_back()
            .map_or(start, |(&s, _)| s);
        for (&s, &e) in self.map.range(from..) {
            if s > end {
                break;
            }
            if e < start {
                continue;
            }
            absorbed.push(s);
            start = start.min(s);
            end = end.max(e);
            let lo = s.max(range.start);
            let hi = e.min(range.end);
            already_covered += hi.saturating_sub(lo);
        }
        for s in absorbed {
            self.map.remove(&s);
        }
        self.map.insert(start, end);
        range.len() - already_covered
    }

    /// Removes `[start, end)` and returns how many bytes were removed. Splits intervals when the
    /// removed range lies inside one.
    pub fn remove(&mut self, range: ByteRange) -> u64 {
        if range.is_empty() {
            return 0;
        }
        let from = self
            .map
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(&s, _)| s);
        let hit: Vec<(u64, u64)> = self
            .map
            .range(from..range.end)
            .filter(|(_, e)| **e > range.start)
            .map(|(&s, &e)| (s, e))
            .collect();
        let mut removed = 0;
        for (s, e) in hit {
            self.map.remove(&s);
            if s < range.start {
                self.map.insert(s, range.start);
            }
            if e > range.end {
                self.map.insert(range.end, e);
            }
            removed += e.min(range.end) - s.max(range.start);
        }
        removed
    }

    /// Removes everything and returns how many bytes were covered.
    pub fn clear(&mut self) -> u64 {
        let n = self.covered_bytes();
        self.map.clear();
        n
    }

    /// True when `offset` is covered.
    #[must_use]
    pub fn contains(&self, offset: u64) -> bool {
        self.map
            .range(..=offset)
            .next_back()
            .is_some_and(|(_, &e)| offset < e)
    }

    /// True when every byte of `range` is covered (an empty range is trivially covered).
    #[must_use]
    pub fn contains_range(&self, range: ByteRange) -> bool {
        range.is_empty()
            || self
                .map
                .range(..=range.start)
                .next_back()
                .is_some_and(|(_, &e)| range.end <= e)
    }

    /// Number of covered bytes: the committed-byte count that becomes `Progress.bytes_done`.
    #[must_use]
    pub fn covered_bytes(&self) -> u64 {
        self.map.iter().map(|(s, e)| e - s).sum()
    }

    /// Covered bytes inside `range`.
    #[must_use]
    pub fn covered_in(&self, range: ByteRange) -> u64 {
        if range.is_empty() {
            return 0;
        }
        let from = self
            .map
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(&s, _)| s);
        self.map
            .range(from..range.end)
            .map(|(&s, &e)| e.min(range.end).saturating_sub(s.max(range.start)))
            .sum()
    }

    /// Number of intervals (a clean sequential download has 1).
    #[must_use]
    pub fn interval_count(&self) -> usize {
        self.map.len()
    }

    /// True when nothing is covered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The covered intervals in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = ByteRange> + '_ {
        // Intervals are validated on insertion, so `new` cannot fail; fall back to an empty range.
        self.map
            .iter()
            .map(|(&s, &e)| ByteRange::new(s, e).unwrap_or(ByteRange { start: s, end: s }))
    }

    /// The end of the covered prefix: the first uncovered offset at or after zero.
    #[must_use]
    pub fn contiguous_prefix(&self) -> u64 {
        match self.map.first_key_value() {
            Some((&0, &e)) => e,
            _ => 0,
        }
    }

    /// The uncovered intervals inside `[0, total)`, ascending: the complement the scheduler plans from.
    #[must_use]
    pub fn uncovered(&self, total: u64) -> Vec<ByteRange> {
        self.uncovered_in(ByteRange {
            start: 0,
            end: total,
        })
    }

    /// The uncovered intervals inside `range`, ascending.
    #[must_use]
    pub fn uncovered_in(&self, range: ByteRange) -> Vec<ByteRange> {
        let mut out = Vec::new();
        let mut cursor = range.start;
        let from = self
            .map
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(&s, _)| s);
        for (&s, &e) in self.map.range(from..range.end) {
            if e <= cursor {
                continue;
            }
            if s > cursor {
                out.push(ByteRange {
                    start: cursor,
                    end: s.min(range.end),
                });
            }
            cursor = cursor.max(e);
            if cursor >= range.end {
                break;
            }
        }
        if cursor < range.end {
            out.push(ByteRange {
                start: cursor,
                end: range.end,
            });
        }
        out
    }

    /// True when `[0, total)` is fully covered: the condition for transition S20.
    #[must_use]
    pub fn is_complete(&self, total: u64) -> bool {
        total == 0
            || self.contains_range(ByteRange {
                start: 0,
                end: total,
            })
    }

    /// The union of two sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for r in other.iter() {
            out.insert(r);
        }
        out
    }

    /// The bytes covered by both sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        let mut out = Self::new();
        for r in other.iter() {
            let from = self
                .map
                .range(..=r.start)
                .next_back()
                .map_or(r.start, |(&s, _)| s);
            for (&s, &e) in self.map.range(from..r.end) {
                let (lo, hi) = (s.max(r.start), e.min(r.end));
                if lo < hi {
                    out.insert(ByteRange { start: lo, end: hi });
                }
            }
        }
        out
    }

    /// The bytes covered by `self` and not by `other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for r in other.iter() {
            out.remove(r);
        }
        out
    }

    /// Checks invariant I4: intervals non-empty, sorted, disjoint, non-adjacent and, when `total` is
    /// known, inside `[0, total)`. A set built through this type's methods always passes; the check
    /// exists for data read back from storage.
    pub fn check_normal_form(&self, total: Option<u64>) -> Result<(), NormalFormError> {
        let mut previous_end: Option<(u64, u64)> = None;
        for (&s, &e) in &self.map {
            if s >= e {
                return Err(NormalFormError::EmptyInterval { start: s });
            }
            if let Some((ps, pe)) = previous_end
                && s <= pe
            {
                return Err(NormalFormError::NotDisjoint {
                    first_start: ps,
                    second_start: s,
                });
            }
            if let Some(t) = total
                && e > t
            {
                return Err(NormalFormError::BeyondTotal { end: e, total: t });
            }
            previous_end = Some((s, e));
        }
        Ok(())
    }

    /// Drops every interval part beyond `total` (recovery step 5 of 03 section 10) and returns the
    /// number of bytes removed.
    pub fn truncate_to(&mut self, total: u64) -> u64 {
        match ByteRange::new(total, u64::MAX >> 11) {
            Ok(tail) => self.remove(tail),
            Err(_) => 0,
        }
    }

    /// Builds a set from stored `(start, end)` pairs, rejecting an inverted pair.
    pub fn try_from_pairs(pairs: impl IntoIterator<Item = (u64, u64)>) -> Result<Self, TypesError> {
        let mut set = Self::new();
        for (s, e) in pairs {
            set.insert(ByteRange::new(s, e)?);
        }
        Ok(set)
    }
}

impl From<Vec<ByteRange>> for RangeSet {
    fn from(ranges: Vec<ByteRange>) -> Self {
        Self::from_ranges(ranges)
    }
}

impl From<RangeSet> for Vec<ByteRange> {
    fn from(set: RangeSet) -> Self {
        set.iter().collect()
    }
}

impl FromIterator<ByteRange> for RangeSet {
    fn from_iter<T: IntoIterator<Item = ByteRange>>(iter: T) -> Self {
        Self::from_ranges(iter)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn r(s: u64, e: u64) -> ByteRange {
        ByteRange::new(s, e).unwrap()
    }

    fn pairs(set: &RangeSet) -> Vec<(u64, u64)> {
        set.iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn adjacent_and_overlapping_inserts_merge() {
        let mut s = RangeSet::new();
        assert_eq!(s.insert(r(0, 10)), 10);
        assert_eq!(s.insert(r(10, 20)), 10, "adjacent intervals merge");
        assert_eq!(pairs(&s), [(0, 20)]);
        assert_eq!(s.insert(r(5, 15)), 0, "already covered: idempotent");
        assert_eq!(s.insert(r(30, 40)), 10);
        assert_eq!(
            s.insert(r(15, 35)),
            10,
            "bridges two intervals, 10 new bytes in the gap"
        );
        assert_eq!(pairs(&s), [(0, 40)]);
        assert_eq!(s.insert(r(7, 7)), 0, "empty insert");
    }

    #[test]
    fn remove_splits_intervals() {
        let mut s = RangeSet::from_ranges([r(0, 100)]);
        assert_eq!(s.remove(r(40, 60)), 20);
        assert_eq!(pairs(&s), [(0, 40), (60, 100)]);
        assert_eq!(s.remove(r(0, 10)), 10);
        assert_eq!(s.remove(r(90, 200)), 10);
        assert_eq!(pairs(&s), [(10, 40), (60, 90)]);
        assert_eq!(s.remove(r(40, 60)), 0);
        assert_eq!(s.remove(r(0, 1000)), 60);
        assert!(s.is_empty());
    }

    #[test]
    fn uncovered_is_the_complement() {
        let s = RangeSet::from_ranges([r(10, 20), r(30, 40)]);
        let gaps: Vec<_> = s
            .uncovered(50)
            .into_iter()
            .map(|g| (g.start, g.end))
            .collect();
        assert_eq!(gaps, [(0, 10), (20, 30), (40, 50)]);
        assert_eq!(s.uncovered(35).len(), 2, "the complement stops at total");
        assert!(RangeSet::from_ranges([r(0, 50)]).uncovered(50).is_empty());
        assert_eq!(RangeSet::new().uncovered(8), vec![r(0, 8)]);
        assert!(s.uncovered(0).is_empty());
    }

    #[test]
    fn coverage_queries() {
        let s = RangeSet::from_ranges([r(0, 10), r(20, 30)]);
        assert!(s.contains(0) && s.contains(9) && !s.contains(10) && s.contains(25));
        assert!(
            s.contains_range(r(2, 8)) && !s.contains_range(r(5, 25)) && s.contains_range(r(4, 4))
        );
        assert_eq!(s.covered_bytes(), 20);
        assert_eq!(s.covered_in(r(5, 25)), 10);
        assert_eq!(s.contiguous_prefix(), 10);
        assert_eq!(RangeSet::from_ranges([r(5, 9)]).contiguous_prefix(), 0);
        assert!(!s.is_complete(30));
        assert!(RangeSet::from_ranges([r(0, 30)]).is_complete(30));
        assert!(RangeSet::new().is_complete(0));
    }

    #[test]
    fn set_algebra() {
        let a = RangeSet::from_ranges([r(0, 10), r(20, 30)]);
        let b = RangeSet::from_ranges([r(5, 25)]);
        assert_eq!(pairs(&a.union(&b)), [(0, 30)]);
        assert_eq!(pairs(&a.intersection(&b)), [(5, 10), (20, 25)]);
        assert_eq!(pairs(&a.difference(&b)), [(0, 5), (25, 30)]);
    }

    #[test]
    fn truncate_to_total() {
        let mut s = RangeSet::from_ranges([r(0, 100), r(200, 300)]);
        assert_eq!(s.truncate_to(250), 50);
        assert_eq!(pairs(&s), [(0, 100), (200, 250)]);
        assert!(s.check_normal_form(Some(250)).is_ok());
        assert!(s.check_normal_form(Some(240)).is_err());
    }

    #[test]
    fn serde_round_trip_normalises() {
        let s: RangeSet = serde_json::from_str(
            r#"[{"start":10,"end":20},{"start":0,"end":10},{"start":30,"end":40}]"#,
        )
        .unwrap();
        assert_eq!(pairs(&s), [(0, 20), (30, 40)]);
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"[{"start":0,"end":20},{"start":30,"end":40}]"#
        );
    }

    #[test]
    fn try_from_pairs_rejects_inverted() {
        assert!(RangeSet::try_from_pairs([(5, 1)]).is_err());
        assert_eq!(
            pairs(&RangeSet::try_from_pairs([(1, 5), (5, 9)]).unwrap()),
            [(1, 9)]
        );
    }

    // ---- property tests against a naive bit-set model over offsets 0..N ----

    const N: u64 = 200;

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u64, u64),
        Remove(u64, u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        (any::<bool>(), 0..N, 0..N).prop_map(|(ins, a, b)| {
            let (s, e) = (a.min(b), a.max(b));
            if ins {
                Op::Insert(s, e)
            } else {
                Op::Remove(s, e)
            }
        })
    }

    fn model_bits(bits: &[bool]) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bits.len() {
            if bits[i] {
                let start = i;
                while i < bits.len() && bits[i] {
                    i += 1;
                }
                out.push((start as u64, i as u64));
            } else {
                i += 1;
            }
        }
        out
    }

    proptest! {
        /// I4: after any sequence of inserts and removes the set is in normal form and equals the model;
        /// the returned byte counts equal the model's changes.
        #[test]
        fn matches_the_bitset_model(ops in proptest::collection::vec(op(), 0..60)) {
            let mut set = RangeSet::new();
            let mut bits = vec![false; N as usize];
            for op in ops {
                match op {
                    Op::Insert(s, e) => {
                        let newly = set.insert(r(s, e));
                        let mut model_new = 0;
                        for b in &mut bits[s as usize..e as usize] { if !*b { *b = true; model_new += 1; } }
                        prop_assert_eq!(newly, model_new);
                    }
                    Op::Remove(s, e) => {
                        let removed = set.remove(r(s, e));
                        let mut model_removed = 0;
                        for b in &mut bits[s as usize..e as usize] { if *b { *b = false; model_removed += 1; } }
                        prop_assert_eq!(removed, model_removed);
                    }
                }
                prop_assert!(set.check_normal_form(Some(N)).is_ok());
            }
            prop_assert_eq!(pairs(&set), model_bits(&bits));
            prop_assert_eq!(set.covered_bytes(), bits.iter().filter(|b| **b).count() as u64);
            // The complement plus the set tile [0, N) exactly.
            let gaps: u64 = set.uncovered(N).iter().map(|g| g.len()).sum();
            prop_assert_eq!(gaps + set.covered_bytes(), N);
            for off in 0..N { prop_assert_eq!(set.contains(off), bits[off as usize]); }
        }

        /// Insertion is idempotent and commutative as a set operation.
        #[test]
        fn insert_is_idempotent_and_order_independent(
            mut ranges in proptest::collection::vec((0..N, 0..N), 0..20),
            shuffle_seed in any::<u64>(),
        ) {
            let rs: Vec<ByteRange> = ranges.iter().map(|&(a, b)| r(a.min(b), a.max(b))).collect();
            let forward = RangeSet::from_ranges(rs.clone());
            let mut twice = forward.clone();
            for x in &rs { prop_assert_eq!(twice.insert(*x), 0); }
            prop_assert_eq!(&forward, &twice);
            // A deterministic shuffle of the same ranges gives the same set.
            let mut rng = zeus_shuffle(shuffle_seed);
            ranges.sort_by_key(|_| rng());
            let shuffled = RangeSet::from_ranges(ranges.iter().map(|&(a, b)| r(a.min(b), a.max(b))));
            prop_assert_eq!(forward, shuffled);
        }

        /// Set algebra agrees with the model.
        #[test]
        fn algebra_matches_the_model(
            xs in proptest::collection::vec((0..N, 0..N), 0..10),
            ys in proptest::collection::vec((0..N, 0..N), 0..10),
        ) {
            let build = |v: &[(u64, u64)]| RangeSet::from_ranges(v.iter().map(|&(a, b)| r(a.min(b), a.max(b))));
            let (a, b) = (build(&xs), build(&ys));
            for off in 0..N {
                prop_assert_eq!(a.union(&b).contains(off), a.contains(off) || b.contains(off));
                prop_assert_eq!(a.intersection(&b).contains(off), a.contains(off) && b.contains(off));
                prop_assert_eq!(a.difference(&b).contains(off), a.contains(off) && !b.contains(off));
            }
            prop_assert!(a.union(&b).check_normal_form(None).is_ok());
            prop_assert!(a.intersection(&b).check_normal_form(None).is_ok());
            prop_assert!(a.difference(&b).check_normal_form(None).is_ok());
        }
    }

    /// A tiny xorshift closure for deterministic shuffling inside a property test.
    fn zeus_shuffle(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed | 1;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }
}
