//! # User support and hooks module
#![deny(missing_docs)]
#[cfg(feature = "alloc")]
use spacepackets::cfdp::tlv::WritableTlv;
use spacepackets::{
    cfdp::{
        ConditionCode,
        pdu::{
            file_data::SegmentMetadata,
            finished::{DeliveryCode, FileStatus},
        },
        tlv::msg_to_user::MsgToUserTlv,
    },
    util::UnsignedByteField,
};

use super::TransactionId;

/// Parameters related to a finished transfer.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransactionFinishedParams {
    /// ID of the transfer.
    pub id: TransactionId,
    /// Condition code.
    pub condition_code: ConditionCode,
    /// Delivery code.
    pub delivery_code: DeliveryCode,
    /// File status.
    pub file_status: FileStatus,
}

/// Parameters related to the reception of a metadata PDU, which might start file reception.
#[derive(Debug)]
pub struct MetadataReceivedParams<'src_file, 'dest_file, 'msgs_to_user> {
    /// ID of the transfer.
    pub id: TransactionId,
    /// Source entity ID.
    pub source_id: UnsignedByteField,
    /// File size.
    pub file_size: u64,
    /// Source file name.
    pub src_file_name: &'src_file str,
    /// Destination file name.
    pub dest_file_name: &'dest_file str,
    /// Messages to user TLVs.
    pub msgs_to_user: &'msgs_to_user [MsgToUserTlv<'msgs_to_user>],
}

/// Owned variant of [MetadataReceivedParams].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct OwnedMetadataRecvdParams {
    /// ID of the transfer.
    pub id: TransactionId,
    /// Source entity ID.
    pub source_id: UnsignedByteField,
    /// File size.
    pub file_size: u64,
    /// Source file name.
    pub src_file_name: alloc::string::String,
    /// Destination file name.
    pub dest_file_name: alloc::string::String,
    /// Messages to user TLVs.
    pub msgs_to_user: alloc::vec::Vec<alloc::vec::Vec<u8>>,
}

#[cfg(feature = "alloc")]
impl From<MetadataReceivedParams<'_, '_, '_>> for OwnedMetadataRecvdParams {
    fn from(value: MetadataReceivedParams) -> Self {
        Self::from(&value)
    }
}

#[cfg(feature = "alloc")]
impl From<&MetadataReceivedParams<'_, '_, '_>> for OwnedMetadataRecvdParams {
    fn from(value: &MetadataReceivedParams) -> Self {
        Self {
            id: value.id,
            source_id: value.source_id,
            file_size: value.file_size,
            src_file_name: value.src_file_name.into(),
            dest_file_name: value.dest_file_name.into(),
            msgs_to_user: value.msgs_to_user.iter().map(|tlv| tlv.to_vec()).collect(),
        }
    }
}

/// Parameters related to the reception of a file segment PDU.
#[derive(Debug)]
pub struct FileSegmentRecvdParams<'seg_meta> {
    /// ID of the transfer.
    pub id: TransactionId,
    /// Offset of the segment.
    pub offset: u64,
    /// Length of the segment.
    pub length: usize,
    /// Segment metadata, if present.
    pub segment_metadata: Option<&'seg_meta SegmentMetadata<'seg_meta>>,
}

/// Generic CFDP user as specified in the CFDP standard.
///
/// This trait declares all indications which are possible.
pub trait CfdpUser {
    /// Indication that a new transaction has started.
    fn transaction_indication(&mut self, id: &TransactionId);

    /// Indication that an EOF PDU has been sent.
    fn eof_sent_indication(&mut self, id: &TransactionId);

    /// Indication that a transaction has finished.
    fn transaction_finished_indication(&mut self, finished_params: &TransactionFinishedParams);

    /// Indication that metadata has been received.
    fn metadata_recvd_indication(&mut self, md_recvd_params: &MetadataReceivedParams);

    /// Indication that a file segment has been received.
    fn file_segment_recvd_indication(&mut self, segment_recvd_params: &FileSegmentRecvdParams);

    // TODO: The standard does not strictly specify how the report information looks..
    /// Report information indication.
    fn report_indication(&mut self, id: &TransactionId);

    /// Indication that a transfer has been suspended.
    fn suspended_indication(&mut self, id: &TransactionId, condition_code: ConditionCode);
    /// Indication that a transfer has been resumed.
    fn resumed_indication(&mut self, id: &TransactionId, progress: u64);

    /// Indication that a fault has occured.
    fn fault_indication(
        &mut self,
        id: &TransactionId,
        condition_code: ConditionCode,
        progress: u64,
    );

    /// Indication that a transfer has been abandoned.
    fn abandoned_indication(
        &mut self,
        id: &TransactionId,
        condition_code: ConditionCode,
        progress: u64,
    );

    /// Indication that an EOF PDU has been received.
    fn eof_recvd_indication(&mut self, id: &TransactionId);
}
