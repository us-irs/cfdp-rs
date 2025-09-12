//! # Lost Segment Store Module
//!
//! The core abstraction provided by this module in the [LostSegmentStore].
//!
//! The two concrete implementations provided are:
//!
//! * [LostSegmentsList]: A hash set based implementation which can grow dynamically andcan
//!   optionally be bounded. Suitable for systems where dynamic allocation is allowed.
//! * [LostSegmentsListHeapless]: A fixed-size list based implementation where the size
//!   of the lost segment list is statically known at compile-time. Suitable for resource
//!   constrained devices where dyanamic allocation is not allowed or possible.

use spacepackets::cfdp::{LargeFileFlag, pdu::nak::NakPduCreatorWithReservedSeqReqsBuf};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LostSegmentError {
    #[error("store is full")]
    StoreFull,
    #[error("segment is empty")]
    EmptySegment,
    #[error("segment start {0} is larger than segment end {1}")]
    StartLargerThanEnd(u64, u64),
    #[error("large file segments are not supported")]
    LargeFileSegmentNotSupported,
    #[error("invalid segment boundary detected for lost segment ({0}, {1})")]
    InvalidSegmentBoundary(u64, u64),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LostSegmentWriteError {
    #[error("number of segments mismatch: expected {expected}, actual {actual}")]
    NumberOfSegmentsMismatch { expected: usize, actual: usize },
    #[error("buffer size not equal to required size")]
    BufferSizeMissmatch { expected: usize, actual: usize },
    #[error("large file segment not compatible to normal file size")]
    LargeSegmentForNormalFileSize,
}

/// Generic trait to model a lost segment store.
///
/// The destination handler can use this store to keep track of lost segments and re-requesting
/// them. This abstraction allow using different data structures as a backend.
pub trait LostSegmentStore {
    // Iteration
    type Iter<'a>: Iterator<Item = (u64, u64)> + 'a
    where
        Self: 'a;

    /// Iterate over all lost segments stored.
    fn iter(&self) -> Self::Iter<'_>;

    /// Current number of lost segments stored.
    fn number_of_segments(&self) -> usize;

    /// Implementations may explicitely omit support for large file segments to save memory if
    /// large file sizes are not used.
    fn supports_large_file_size(&self) -> bool;
    fn capacity(&self) -> Option<usize>;
    fn reset(&mut self);

    /// Checks whether a segment is already in the store.
    ///
    /// Implementors should be check whether the provided segment is a subset of an existing
    /// segments.
    fn segment_in_store(&self, segment: (u64, u64)) -> bool;

    /// Add a new lost segment.
    ///
    /// For efficiency reason, the implementors must not check whether the new segments already
    /// exists in the store which is provided by the [Self::segment_in_store] method.
    ///
    /// Therefore, the caller must ensure that no duplicate segments are added.
    fn add_lost_segment(&mut self, lost_seg: (u64, u64)) -> Result<(), LostSegmentError>;

    /// Remove a lost segment.
    ///
    /// Implementors should also be able to remove lost segments which are a subset of an existing
    /// section but can return an error if an segment to remove only partially overlaps an existing
    /// segment.
    ///
    /// Returns whether a segment was removed.
    fn remove_lost_segment(
        &mut self,
        segment_to_remove: (u64, u64),
    ) -> Result<bool, LostSegmentError>;

    /// The lost segment store may additionally have the capability to coalesce overlapping or
    /// adjacent segments.
    fn coalesce_lost_segments(&mut self) -> Result<(), LostSegmentError>;

    #[inline]
    fn is_empty(&self) -> bool {
        self.number_of_segments() == 0
    }

    /// Write the segments to the raw byte format of the NAK PDU segment requests as specified by
    /// the CFDP standard 5.2.6.1 (NAK PDU).
    fn write_segments_to_bytes(
        &self,
        buf: &mut [u8],
        file_flag: LargeFileFlag,
    ) -> Result<usize, LostSegmentWriteError> {
        let len_per_segment = if file_flag == LargeFileFlag::Large {
            16
        } else {
            8
        };
        let written_len = self.number_of_segments() * len_per_segment;
        if written_len != buf.len() {
            return Err(LostSegmentWriteError::BufferSizeMissmatch {
                expected: written_len,
                actual: buf.len(),
            });
        }
        let mut current_index = 0;
        for segment in self.iter() {
            match file_flag {
                LargeFileFlag::Normal => {
                    if segment.0 > u32::MAX as u64 || segment.1 > u32::MAX as u64 {
                        return Err(LostSegmentWriteError::LargeSegmentForNormalFileSize);
                    }
                    buf[current_index..current_index + 4]
                        .copy_from_slice(&(segment.0 as u32).to_be_bytes());
                    current_index += 4;
                    buf[current_index..current_index + 4]
                        .copy_from_slice(&(segment.1 as u32).to_be_bytes());
                    current_index += 4;
                }
                LargeFileFlag::Large => {
                    buf[current_index..current_index + 8]
                        .copy_from_slice(&(segment.0).to_be_bytes());
                    current_index += 8;
                    buf[current_index..current_index + 8]
                        .copy_from_slice(&(segment.1).to_be_bytes());
                    current_index += 8;
                }
            }
        }
        Ok(current_index)
    }

    /// Write the segments to the raw byte buffer of the supplied
    /// [NAK builder][NakPduCreatorWithReservedSeqReqsBuf].
    ///
    /// Please note that this function only works if all the segment requests fit into the NAK
    /// builder buffer. In any other case, you should write a custom iteration and serialization
    /// sequence which spreads the lost segments across multiple packets.
    fn write_to_nak_segment_list(
        &self,
        nak_builder: &mut NakPduCreatorWithReservedSeqReqsBuf,
        first_segment_request_for_metadata: bool,
    ) -> Result<usize, LostSegmentWriteError> {
        let file_flag = nak_builder.pdu_header().common_pdu_conf().file_flag;
        let mut relevant_size = self.number_of_segments();
        if first_segment_request_for_metadata {
            relevant_size += 1;
        }
        if nak_builder.num_segment_reqs() != relevant_size {
            return Err(LostSegmentWriteError::NumberOfSegmentsMismatch {
                expected: self.number_of_segments(),
                actual: nak_builder.num_segment_reqs(),
            });
        }
        let mut buf = nak_builder.segment_request_buffer_mut();
        let mut written_len = 0;
        if first_segment_request_for_metadata {
            match file_flag {
                LargeFileFlag::Normal => {
                    buf[0..8].fill(0);
                    buf = &mut buf[8..];
                    written_len += 8;
                }
                LargeFileFlag::Large => {
                    buf[0..16].fill(0);
                    buf = &mut buf[16..];
                    written_len += 16;
                }
            }
        }
        written_len += self.write_segments_to_bytes(buf, file_flag)?;
        Ok(written_len)
    }
}

/// Implementation based on a [alloc::vec::Vec] which can grow dynamically.
///
/// Optionally, a maximum capacity can be specified at creation time. This container allocates at
/// run-time!
#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct LostSegmentsList {
    list: alloc::vec::Vec<(u64, u64)>,
    opt_capacity: Option<usize>,
}

#[cfg(feature = "alloc")]
impl LostSegmentsList {
    pub fn new(opt_capacity: Option<usize>) -> Self {
        Self {
            list: alloc::vec::Vec::new(),
            opt_capacity,
        }
    }
}

#[cfg(feature = "alloc")]
impl LostSegmentStore for LostSegmentsList {
    type Iter<'a>
        = core::iter::Cloned<core::slice::Iter<'a, (u64, u64)>>
    where
        Self: 'a;

    fn iter(&self) -> Self::Iter<'_> {
        self.list.iter().cloned()
    }

    #[inline]
    fn number_of_segments(&self) -> usize {
        self.list.len()
    }

    #[inline]
    fn supports_large_file_size(&self) -> bool {
        true
    }

    #[inline]
    fn capacity(&self) -> Option<usize> {
        self.opt_capacity
    }

    #[inline]
    fn reset(&mut self) {
        self.list.clear();
    }

    fn segment_in_store(&self, segment: (u64, u64)) -> bool {
        for (seg_start, seg_end) in &self.list {
            if segment.0 >= *seg_start && segment.1 <= *seg_end {
                return true;
            }
        }
        false
    }

    #[inline]
    fn add_lost_segment(&mut self, lost_seg: (u64, u64)) -> Result<(), LostSegmentError> {
        if lost_seg.1 == lost_seg.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if lost_seg.0 > lost_seg.1 {
            return Err(LostSegmentError::StartLargerThanEnd(lost_seg.0, lost_seg.1));
        }
        if let Some(capacity) = self.opt_capacity {
            if self.list.len() == capacity {
                return Err(LostSegmentError::StoreFull);
            }
        }
        self.list.push((lost_seg.0, lost_seg.1));
        Ok(())
    }

    fn coalesce_lost_segments(&mut self) -> Result<(), LostSegmentError> {
        // Remove empty/invalid ranges
        self.list.retain(|&(s, e)| e > s);
        if self.list.len() <= 1 {
            return Ok(());
        }

        // Sort by start, then end (no extra allocs)
        self.list
            .as_mut_slice()
            .sort_unstable_by_key(|&(start, _)| start);

        // In-place merge; merges overlapping or adjacent [s, e) where next.s <= prev.e
        let mut w = 0usize;
        for i in 0..self.list.len() {
            if w == 0 {
                self.list[w] = self.list[i];
                w = 1;
                continue;
            }

            let (prev_s, mut prev_e) = self.list[w - 1];
            let (s, e) = self.list[i];

            if s <= prev_e {
                // Extend previous
                if e > prev_e {
                    prev_e = e;
                    self.list[w - 1] = (prev_s, prev_e);
                }
            } else {
                // Start new merged interval
                self.list[w] = (s, e);
                w += 1;
            }
        }

        // Truncate to merged length
        self.list.truncate(w);
        Ok(())
    }

    #[inline]
    fn remove_lost_segment(
        &mut self,
        segment_to_remove: (u64, u64),
    ) -> Result<bool, LostSegmentError> {
        if segment_to_remove.1 == segment_to_remove.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if segment_to_remove.0 > segment_to_remove.1 {
            return Err(LostSegmentError::StartLargerThanEnd(
                segment_to_remove.0,
                segment_to_remove.1,
            ));
        }

        // Binary search for the first candidate.
        let idx = match self
            .list
            .binary_search_by_key(&segment_to_remove.0, |&(s, _)| s)
        {
            Ok(idx) => idx,
            Err(insertion) => insertion.saturating_sub(1),
        };

        // --- single linear scan -------------------------------------------------
        let mut i = idx;
        let list_len = self.list.len();
        while i < self.list.len() && self.list[i].0 <= segment_to_remove.1 {
            let seg = &mut self.list[i];

            // no overlap
            if seg.1 < segment_to_remove.0 {
                i += 1;
                continue;
            }

            // exact match → remove whole segment
            if seg == &segment_to_remove {
                self.list.remove(i);
                // keep `i` unchanged: we swapped the tail element forward
                return Ok(true);
            }

            // partial overlap → forbidden
            if (segment_to_remove.0 < seg.0 && segment_to_remove.1 > seg.0)
                || (segment_to_remove.1 > seg.1 && segment_to_remove.0 < seg.1)
            {
                return Err(LostSegmentError::InvalidSegmentBoundary(
                    segment_to_remove.0,
                    segment_to_remove.1,
                ));
            }

            // Removal of subset.

            let mut changed = false;

            // Removal touches right edge only → shorten from the right
            if segment_to_remove.1 == seg.1 {
                seg.1 = segment_to_remove.0;
                changed = true;
            }
            // Removal touches left edge only → shorten from the left
            if segment_to_remove.0 == seg.0 {
                seg.0 = segment_to_remove.1;
                changed = true;
            }
            // Removal is strictly inside → split into two parts
            if segment_to_remove.0 > seg.0 && segment_to_remove.1 < seg.1 {
                if list_len == self.opt_capacity.unwrap_or(usize::MAX) {
                    return Err(LostSegmentError::StoreFull);
                }
                // Right remainder.
                let end_of_right_remainder = seg.1;
                // Left remainder.
                seg.1 = segment_to_remove.0;
                self.list
                    .insert(i + 1, (segment_to_remove.1, end_of_right_remainder));
                changed = true;
            }

            // when both sides remain we truncated the current segment already
            if changed {
                return Ok(true);
            }

            i += 1;
        }
        Ok(false)
    }
}

/// Implementation based on a [heapless::Vec] with a statically known container size.
#[derive(Default, Debug)]
pub struct LostSegmentsListHeapless<const N: usize, T> {
    list: heapless::vec::Vec<(T, T), N>,
}

/// Type definition for segment list which only supports normal file sizes. This can be used
/// to save memory required for the lost segment list.
pub type LostSegmentsListNormalFilesHeapless<const N: usize> = LostSegmentsListHeapless<N, u32>;

impl<const N: usize, T> LostSegmentsListHeapless<N, T> {
    pub fn new() -> Self {
        Self {
            list: heapless::Vec::new(),
        }
    }

    #[inline]
    fn num_lost_segments(&self) -> usize {
        self.list.len()
    }

    #[inline]
    fn capacity(&self) -> Option<usize> {
        Some(N)
    }

    #[inline]
    fn reset(&mut self) {
        self.list.clear();
    }
}

impl<const N: usize, T: Copy + Clone + Ord> LostSegmentsListHeapless<N, T> {
    fn coalesce_lost_segments(&mut self) -> Result<(), LostSegmentError> {
        // Remove empty/invalid ranges
        self.list.retain(|&(s, e)| e > s);
        if self.list.len() <= 1 {
            return Ok(());
        }

        // Sort by start, then end (no extra allocs)
        self.list
            .as_mut_slice()
            .sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // In-place merge; merges overlapping or adjacent [s, e) where next.s <= prev.e
        let mut w = 0usize;
        for i in 0..self.list.len() {
            if w == 0 {
                self.list[w] = self.list[i];
                w = 1;
                continue;
            }

            let (prev_s, mut prev_e) = self.list[w - 1];
            let (s, e) = self.list[i];

            if s <= prev_e {
                // Extend previous
                if e > prev_e {
                    prev_e = e;
                    self.list[w - 1] = (prev_s, prev_e);
                }
            } else {
                // Start new merged interval
                self.list[w] = (s, e);
                w += 1;
            }
        }

        // Truncate to merged length
        self.list.truncate(w);
        Ok(())
    }
}

impl<const N: usize> LostSegmentStore for LostSegmentsListHeapless<N, u64> {
    type Iter<'a>
        = core::iter::Cloned<core::slice::Iter<'a, (u64, u64)>>
    where
        Self: 'a;

    fn iter(&self) -> Self::Iter<'_> {
        self.list.iter().cloned()
    }

    fn add_lost_segment(&mut self, lost_seg: (u64, u64)) -> Result<(), LostSegmentError> {
        if lost_seg.1 == lost_seg.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if lost_seg.0 > lost_seg.1 {
            return Err(LostSegmentError::StartLargerThanEnd(lost_seg.0, lost_seg.1));
        }
        if self.list.is_full() {
            return Err(LostSegmentError::StoreFull);
        }
        self.list.push(lost_seg).ok();
        Ok(())
    }

    fn remove_lost_segment(
        &mut self,
        segment_to_remove: (u64, u64),
    ) -> Result<bool, LostSegmentError> {
        if segment_to_remove.1 == segment_to_remove.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if segment_to_remove.0 > segment_to_remove.1 {
            return Err(LostSegmentError::StartLargerThanEnd(
                segment_to_remove.0,
                segment_to_remove.1,
            ));
        }

        // Binary search for the first candidate.
        let idx = match self
            .list
            .binary_search_by_key(&segment_to_remove.0, |&(s, _)| s)
        {
            Ok(idx) => idx,
            Err(insertion) => insertion.saturating_sub(1),
        };

        // --- single linear scan -------------------------------------------------
        let mut i = idx;
        let list_len = self.list.len();
        while i < self.list.len() && self.list[i].0 <= segment_to_remove.1 {
            let seg = &mut self.list[i];

            // no overlap
            if seg.1 < segment_to_remove.0 {
                i += 1;
                continue;
            }

            // exact match → remove whole segment
            if seg == &segment_to_remove {
                self.list.remove(i);
                return Ok(true);
            }

            // partial overlap → forbidden
            if (segment_to_remove.0 < seg.0 && segment_to_remove.1 > seg.0)
                || (segment_to_remove.1 > seg.1 && segment_to_remove.0 < seg.1)
            {
                return Err(LostSegmentError::InvalidSegmentBoundary(
                    segment_to_remove.0,
                    segment_to_remove.1,
                ));
            }

            // Removal of subset.

            let mut changed = false;

            // Removal touches right edge only → shorten from the right
            if segment_to_remove.1 == seg.1 {
                seg.1 = segment_to_remove.0;
                changed = true;
            }
            // Removal touches left edge only → shorten from the left
            if segment_to_remove.0 == seg.0 {
                seg.0 = segment_to_remove.1;
                changed = true;
            }
            // Removal is strictly inside → split into two parts
            if segment_to_remove.0 > seg.0 && segment_to_remove.1 < seg.1 {
                if list_len == N {
                    return Err(LostSegmentError::StoreFull);
                }
                // Right remainder.
                let end_of_right_remainder = seg.1;
                // Left remainder.
                seg.1 = segment_to_remove.0;
                self.list
                    .insert(i + 1, (segment_to_remove.1, end_of_right_remainder))
                    .unwrap();
                changed = true;
            }

            // when both sides remain we truncated the current segment already
            if changed {
                return Ok(true);
            }

            i += 1;
        }
        Ok(false)
    }

    fn coalesce_lost_segments(&mut self) -> Result<(), LostSegmentError> {
        self.coalesce_lost_segments()
    }

    fn number_of_segments(&self) -> usize {
        self.num_lost_segments()
    }

    fn supports_large_file_size(&self) -> bool {
        true
    }

    fn capacity(&self) -> Option<usize> {
        self.capacity()
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn segment_in_store(&self, segment: (u64, u64)) -> bool {
        for (seg_start, seg_end) in &self.list {
            if segment.0 >= *seg_start && segment.1 <= *seg_end {
                return true;
            }
        }
        false
    }
}

impl<const N: usize> LostSegmentStore for LostSegmentsListHeapless<N, u32> {
    type Iter<'a>
        = core::iter::Map<core::slice::Iter<'a, (u32, u32)>, fn(&(u32, u32)) -> (u64, u64)>
    where
        Self: 'a;

    fn iter(&self) -> Self::Iter<'_> {
        self.list.iter().map(|pair| (pair.0 as u64, pair.1 as u64))
    }

    fn add_lost_segment(&mut self, lost_seg: (u64, u64)) -> Result<(), LostSegmentError> {
        if lost_seg.1 == lost_seg.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if lost_seg.0 > lost_seg.1 {
            return Err(LostSegmentError::StartLargerThanEnd(lost_seg.0, lost_seg.1));
        }
        if lost_seg.1 > u32::MAX as u64 || lost_seg.0 > u32::MAX as u64 {
            return Err(LostSegmentError::LargeFileSegmentNotSupported);
        }
        if self.list.is_full() {
            return Err(LostSegmentError::StoreFull);
        }
        self.list.push((lost_seg.0 as u32, lost_seg.1 as u32)).ok();
        Ok(())
    }

    fn remove_lost_segment(
        &mut self,
        segment_to_remove: (u64, u64),
    ) -> Result<bool, LostSegmentError> {
        if segment_to_remove.0 > u32::MAX as u64 || segment_to_remove.1 > u32::MAX as u64 {
            return Err(LostSegmentError::LargeFileSegmentNotSupported);
        }
        if segment_to_remove.1 == segment_to_remove.0 {
            return Err(LostSegmentError::EmptySegment);
        }
        if segment_to_remove.0 > segment_to_remove.1 {
            return Err(LostSegmentError::StartLargerThanEnd(
                segment_to_remove.0,
                segment_to_remove.1,
            ));
        }

        // Binary search for the first candidate.
        let idx = match self
            .list
            .binary_search_by_key(&segment_to_remove.0, |&(s, _)| s as u64)
        {
            Ok(idx) => idx,
            Err(insertion) => insertion.saturating_sub(1),
        };

        // --- single linear scan -------------------------------------------------
        let mut i = idx;
        let list_len = self.list.len();
        while i < self.list.len() && self.list[i].0 as u64 <= segment_to_remove.1 {
            let seg = &mut self.list[i];

            // no overlap
            if (seg.1 as u64) < segment_to_remove.0 {
                i += 1;
                continue;
            }

            // exact match → remove whole segment
            if seg.0 as u64 == segment_to_remove.0 && seg.1 as u64 == segment_to_remove.1 {
                self.list.remove(i);
                return Ok(true);
            }

            // partial overlap → forbidden
            if (segment_to_remove.0 < seg.0 as u64 && segment_to_remove.1 > seg.0 as u64)
                || (segment_to_remove.1 > seg.1 as u64 && segment_to_remove.0 < seg.1 as u64)
            {
                return Err(LostSegmentError::InvalidSegmentBoundary(
                    segment_to_remove.0,
                    segment_to_remove.1,
                ));
            }

            // Removal of subset.

            let mut changed = false;

            // Removal touches right edge only → shorten from the right
            if segment_to_remove.1 == seg.1 as u64 {
                seg.1 = segment_to_remove.0 as u32;
                changed = true;
            }
            // Removal touches left edge only → shorten from the left
            if segment_to_remove.0 == seg.0 as u64 {
                seg.0 = segment_to_remove.1 as u32;
                changed = true;
            }
            // Removal is strictly inside → split into two parts
            if segment_to_remove.0 > seg.0 as u64 && segment_to_remove.1 < seg.1 as u64 {
                if list_len == N {
                    return Err(LostSegmentError::StoreFull);
                }
                // Right remainder.
                let end_of_right_remainder = seg.1;
                // Left remainder.
                seg.1 = segment_to_remove.0 as u32;
                self.list
                    .insert(i + 1, (segment_to_remove.1 as u32, end_of_right_remainder))
                    .unwrap();
                changed = true;
            }

            // when both sides remain we truncated the current segment already
            if changed {
                return Ok(true);
            }

            i += 1;
        }
        Ok(false)
    }

    fn coalesce_lost_segments(&mut self) -> Result<(), LostSegmentError> {
        self.coalesce_lost_segments()
    }

    #[inline]
    fn number_of_segments(&self) -> usize {
        self.num_lost_segments()
    }

    #[inline]
    fn supports_large_file_size(&self) -> bool {
        false
    }

    #[inline]
    fn capacity(&self) -> Option<usize> {
        self.capacity()
    }

    #[inline]
    fn reset(&mut self) {
        self.reset();
    }

    fn segment_in_store(&self, segment: (u64, u64)) -> bool {
        for (seg_start, seg_end) in &self.list {
            if segment.0 >= *seg_start as u64 && segment.1 <= *seg_end as u64 {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn generic_basic_state_test(
        store: &impl LostSegmentStore,
        supports_large_file_size: bool,
        capacity: Option<usize>,
    ) {
        assert_eq!(store.supports_large_file_size(), supports_large_file_size);
        assert_eq!(store.number_of_segments(), 0);
        assert!(store.is_empty());
        assert_eq!(store.capacity(), capacity);
        assert_eq!(store.iter().count(), 0);
    }

    fn generic_error_tests(store: &mut impl LostSegmentStore) {
        matches!(
            store.add_lost_segment((0, 0)).unwrap_err(),
            LostSegmentError::EmptySegment
        );
        matches!(
            store.add_lost_segment((10, 0)).unwrap_err(),
            LostSegmentError::StartLargerThanEnd(10, 0)
        );
        matches!(
            store.remove_lost_segment((0, 0)).unwrap_err(),
            LostSegmentError::EmptySegment
        );
        matches!(
            store.remove_lost_segment((10, 0)).unwrap_err(),
            LostSegmentError::StartLargerThanEnd(10, 0)
        );
    }

    fn generic_add_segments_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        for segment in store.iter() {
            assert_eq!(segment, (0, 20));
        }
        store.add_lost_segment((20, 40)).unwrap();
        let mut segments: Vec<(u64, u64)> = store.iter().collect();
        segments.sort_unstable();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], (0, 20));
        assert_eq!(segments[1], (20, 40));
    }

    fn generic_reset_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        store.reset();
        assert_eq!(store.number_of_segments(), 0);
        assert!(store.is_empty());
        assert_eq!(store.iter().count(), 0);
    }

    fn generic_removal_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        store.add_lost_segment((20, 40)).unwrap();
        assert_eq!(store.number_of_segments(), 2);
        assert!(store.remove_lost_segment((0, 20)).unwrap());
        assert_eq!(store.number_of_segments(), 1);
        assert!(!store.remove_lost_segment((0, 20)).unwrap());
        assert_eq!(store.number_of_segments(), 1);
        assert!(store.remove_lost_segment((20, 40)).unwrap());
        assert_eq!(store.number_of_segments(), 0);
    }

    fn generic_partial_removal_test_right_aligned(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        store.remove_lost_segment((0, 10)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        for list in store.iter() {
            assert_eq!(list, (10, 20));
        }
        store.remove_lost_segment((10, 20)).unwrap();
        assert!(store.is_empty());
    }

    fn generic_partial_removal_test_left_aligned(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        store.remove_lost_segment((10, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        for list in store.iter() {
            assert_eq!(list, (0, 10));
        }
        store.remove_lost_segment((0, 10)).unwrap();
        assert!(store.is_empty());
    }

    fn generic_partial_removal_test_fully_contained(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        store.remove_lost_segment((5, 15)).unwrap();
        assert_eq!(store.number_of_segments(), 2);
        let seg_list = store.iter().collect::<Vec<(u64, u64)>>();
        assert!(seg_list.contains(&(0, 5)));
        assert!(seg_list.contains(&(15, 20)));
        store.remove_lost_segment((0, 5)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        store.remove_lost_segment((15, 20)).unwrap();
        assert!(store.is_empty());
    }

    fn generic_partial_removal_fails_test_0(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((10, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        assert_eq!(
            store.remove_lost_segment((5, 15)).unwrap_err(),
            LostSegmentError::InvalidSegmentBoundary(5, 15)
        );
    }

    fn generic_partial_removal_fails_test_1(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((10, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        assert_eq!(
            store.remove_lost_segment((15, 25)).unwrap_err(),
            LostSegmentError::InvalidSegmentBoundary(15, 25)
        );
    }

    fn generic_partial_removal_fails_test_2(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((10, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        assert_eq!(
            store.remove_lost_segment((10, 25)).unwrap_err(),
            LostSegmentError::InvalidSegmentBoundary(10, 25)
        );
    }

    fn generic_partial_removal_fails_test_3(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((10, 20)).unwrap();
        assert_eq!(store.number_of_segments(), 1);
        assert_eq!(
            store.remove_lost_segment((5, 20)).unwrap_err(),
            LostSegmentError::InvalidSegmentBoundary(5, 20)
        );
    }

    fn generic_coalescing_simple_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        store.add_lost_segment((20, 40)).unwrap();
        store.add_lost_segment((40, 60)).unwrap();
        store.coalesce_lost_segments().unwrap();
        for segment in store.iter() {
            assert_eq!(segment, (0, 60));
        }
        assert_eq!(store.number_of_segments(), 1);
    }

    fn generic_coalescing_simple_with_gaps_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        store.add_lost_segment((20, 40)).unwrap();
        store.add_lost_segment((40, 60)).unwrap();

        store.add_lost_segment((80, 100)).unwrap();
        store.add_lost_segment((110, 120)).unwrap();
        store.add_lost_segment((120, 130)).unwrap();
        store.coalesce_lost_segments().unwrap();
        let mut segments: Vec<(u64, u64)> = store.iter().collect();
        segments.sort_unstable();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], (0, 60));
        assert_eq!(segments[1], (80, 100));
        assert_eq!(segments[2], (110, 130));
    }

    fn generic_coalescing_overlapping_simple_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        store.add_lost_segment((10, 30)).unwrap();
        store.coalesce_lost_segments().unwrap();
        for segment in store.iter() {
            assert_eq!(segment, (0, 30));
        }
        assert_eq!(store.number_of_segments(), 1);
    }

    fn generic_coalescing_overlapping_adjacent_test(store: &mut impl LostSegmentStore) {
        store.add_lost_segment((0, 20)).unwrap();
        store.add_lost_segment((10, 30)).unwrap();
        store.add_lost_segment((20, 40)).unwrap();
        store.coalesce_lost_segments().unwrap();
        for segment in store.iter() {
            assert_eq!(segment, (0, 40));
        }
        assert_eq!(store.number_of_segments(), 1);
    }

    fn generic_useless_coalescing_test(store: &mut impl LostSegmentStore) {
        // Is okay, does nothing.
        assert!(store.coalesce_lost_segments().is_ok());
        assert_eq!(store.number_of_segments(), 0);
        assert!(store.is_empty());
        store.add_lost_segment((10, 20)).unwrap();
        // Is okay, does nothing.
        assert!(store.coalesce_lost_segments().is_ok());
        for segment in store.iter() {
            assert_eq!(segment, (10, 20));
        }
    }

    #[test]
    fn test_basic_map_state_list() {
        let store = LostSegmentsList::default();
        generic_basic_state_test(&store, true, None);
    }

    #[test]
    fn test_basic_errors_list() {
        let mut store = LostSegmentsList::default();
        generic_error_tests(&mut store);
    }

    #[test]
    fn test_add_segments_list() {
        let mut store = LostSegmentsList::default();
        generic_add_segments_test(&mut store);
    }

    #[test]
    fn test_reset_list() {
        let mut store = LostSegmentsList::default();
        generic_reset_test(&mut store);
    }

    #[test]
    fn test_removal_map() {
        let mut store = LostSegmentsList::default();
        generic_removal_test(&mut store);
    }

    #[test]
    fn test_partial_removal_list_0() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_test_right_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_1() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_test_left_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_2() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_test_fully_contained(&mut store);
    }

    #[test]
    fn test_partial_removal_list_fails_0() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_fails_test_0(&mut store);
    }

    #[test]
    fn test_partial_removal_list_fails_1() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_fails_test_1(&mut store);
    }

    #[test]
    fn test_partial_removal_list_fails_2() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_fails_test_2(&mut store);
    }

    #[test]
    fn test_partial_removal_list_fails_3() {
        let mut store = LostSegmentsList::default();
        generic_partial_removal_fails_test_3(&mut store);
    }

    #[test]
    fn test_cap_limit_list() {
        let mut store = LostSegmentsList::new(Some(4));
        for i in 0..4 {
            store.add_lost_segment((i * 20, (i + 1) * 20)).unwrap();
        }
        matches!(
            store.add_lost_segment((80, 100)),
            Err(LostSegmentError::StoreFull)
        );
    }

    #[test]
    fn test_basic_list_state_list() {
        let store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_basic_state_test(&store, false, Some(12));
        let store = LostSegmentsListNormalFilesHeapless::<12>::new();
        generic_basic_state_test(&store, false, Some(12));
    }
    #[test]
    fn test_basic_errors_list_heapless() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_error_tests(&mut store);
    }

    #[test]
    fn test_add_segments_list_heapless() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_add_segments_test(&mut store);
    }

    #[test]
    fn test_reset_list_heapless() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_reset_test(&mut store);
    }

    #[test]
    fn test_removal_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_removal_test(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_0() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_test_right_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_1() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_test_left_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_2() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_test_fully_contained(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_fails_0() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_fails_test_0(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_fails_1() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_fails_test_1(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_fails_2() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_fails_test_2(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_fails_3() {
        let mut store = LostSegmentsListNormalFilesHeapless::<12>::default();
        generic_partial_removal_fails_test_3(&mut store);
    }

    fn generic_cap_limit_list_by_removal_test(store: &mut impl LostSegmentStore) {
        for i in 0..4 {
            store.add_lost_segment((i * 20, (i + 1) * 20)).unwrap();
        }
        // This splits the segments, and the insert attempt should fail.
        matches!(
            store.remove_lost_segment((85, 95)),
            Err(LostSegmentError::StoreFull)
        );
    }

    fn generic_cap_limit_list_by_addition_test(store: &mut impl LostSegmentStore) {
        for i in 0..4 {
            store.add_lost_segment((i * 20, (i + 1) * 20)).unwrap();
        }
        // This splits the segments, and the insert attempt should fail.
        matches!(
            store.add_lost_segment((100, 120)),
            Err(LostSegmentError::StoreFull)
        );
    }

    #[test]
    fn test_cap_limit_list_by_removal() {
        let mut store = LostSegmentsList::new(Some(4));
        generic_cap_limit_list_by_removal_test(&mut store);
    }

    #[test]
    fn test_cap_limit_list_heapless_by_removal() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_cap_limit_list_by_removal_test(&mut store);
    }

    #[test]
    fn test_cap_limit_list_heapless() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_cap_limit_list_by_addition_test(&mut store);
    }

    #[test]
    fn test_large_file_size_unsupported() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        matches!(
            store.add_lost_segment((0, u32::MAX as u64 + 1)),
            Err(LostSegmentError::LargeFileSegmentNotSupported)
        );
    }

    #[test]
    fn test_large_file_size_unsupported_2() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        matches!(
            store.remove_lost_segment((0, u32::MAX as u64 + 1)),
            Err(LostSegmentError::LargeFileSegmentNotSupported)
        );
    }

    #[test]
    fn test_basic_list_state_list_large() {
        let store = LostSegmentsListHeapless::<12, u64>::default();
        generic_basic_state_test(&store, true, Some(12));
    }
    #[test]
    fn test_basic_errors_list_large() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_error_tests(&mut store);
    }

    #[test]
    fn test_add_segments_list_large() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_add_segments_test(&mut store);
    }

    #[test]
    fn test_reset_list_large() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_reset_test(&mut store);
    }

    #[test]
    fn test_removal_list_large() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_removal_test(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_large_0() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_test_right_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_large_1() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_test_left_aligned(&mut store);
    }

    #[test]
    fn test_partial_removal_list_heapless_large_2() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_test_fully_contained(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_large_fails_0() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_fails_test_0(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_large_fails_1() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_fails_test_1(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_large_fails_2() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_fails_test_2(&mut store);
    }

    #[test]
    fn test_partial_removal_heapless_list_large_fails_3() {
        let mut store = LostSegmentsListHeapless::<12, u64>::default();
        generic_partial_removal_fails_test_3(&mut store);
    }

    #[test]
    fn test_cap_limit_list_large() {
        let mut store = LostSegmentsListHeapless::<4, u64>::default();
        generic_cap_limit_list_by_removal_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_in_map() {
        let mut store = LostSegmentsList::default();
        generic_coalescing_simple_test(&mut store);
    }

    #[test]
    fn test_useless_coalescing_map() {
        let mut store = LostSegmentsList::default();
        generic_useless_coalescing_test(&mut store);
    }

    #[test]
    fn test_useless_coalescing_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_useless_coalescing_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_in_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_coalescing_simple_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_in_list_large() {
        let mut store = LostSegmentsListHeapless::<4, u64>::default();
        generic_coalescing_simple_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_simple_in_map() {
        let mut store = LostSegmentsList::default();
        generic_coalescing_overlapping_simple_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_simple_in_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_coalescing_overlapping_simple_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_simple_in_list_large() {
        let mut store = LostSegmentsListHeapless::<4, u64>::default();
        generic_coalescing_overlapping_simple_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_adjacent_in_map() {
        let mut store = LostSegmentsList::default();
        generic_coalescing_overlapping_adjacent_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_adjacent_in_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<4>::default();
        generic_coalescing_overlapping_adjacent_test(&mut store);
    }

    #[test]
    fn test_coalescing_overlapping_adjacent_in_list_large() {
        let mut store = LostSegmentsListHeapless::<4, u64>::default();
        generic_coalescing_overlapping_adjacent_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_with_gaps_in_map() {
        let mut store = LostSegmentsList::default();
        generic_coalescing_simple_with_gaps_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_with_gaps_in_list() {
        let mut store = LostSegmentsListNormalFilesHeapless::<8>::default();
        generic_coalescing_simple_with_gaps_test(&mut store);
    }

    #[test]
    fn test_coalescing_simple_with_gaps_in_list_large() {
        let mut store = LostSegmentsListHeapless::<8, u64>::default();
        generic_coalescing_simple_with_gaps_test(&mut store);
    }
}
