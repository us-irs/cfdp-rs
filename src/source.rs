//! # CFDP Source Entity Module
//!
//! The [SourceHandler] is the primary component of this module which converts a
//! [ReadablePutRequest] into all packet data units (PDUs) which need to be sent to a remote
//! CFDP entity to perform a File Copy operation to a remote entity.
//!
//! The source entity allows freedom communication by using a user-provided [PduSender] instance
//! to send all generated PDUs. It should be noted that for regular file transfers, each
//! [SourceHandler::state_machine] call will map to one generated file data PDU. This allows
//! flow control for the user of the state machine.
//!
//! The [SourceHandler::state_machine] will generally perform the following steps after a valid
//! put request was received through the [SourceHandler::put_request] method:
//!
//! 1. Generate the Metadata PDU to be sent to a remote CFDP entity. You can use the
//!    [spacepackets::cfdp::pdu::metadata::MetadataPduReader] to inspect the generated PDU.
//! 2. Generate all File Data PDUs to be sent to a remote CFDP entity if applicable (file not
//!    empty). The PDU(s) can be inspected using the [spacepackets::cfdp::pdu::file_data::FileDataPdu] reader.
//! 3. Generate an EOF PDU to be sent to a remote CFDP entity. The PDU can be inspected using
//!    the [spacepackets::cfdp::pdu::eof::EofPdu] reader.
//!
//! If this is an unacknowledged transfer with no transaction closure, the file transfer will be
//! done after these steps. In any other case:
//!
//! ### Unacknowledged transfer with requested closure
//!
//! 4. A Finished PDU will be awaited, for example one generated using
//!    [spacepackets::cfdp::pdu::finished::FinishedPduCreator].
//!
//! ### Acknowledged transfer (*not implemented yet*)
//!
//! 4. A EOF ACK packet will be awaited, for example one generated using
//!    [spacepackets::cfdp::pdu::ack::AckPdu].
//! 5. A Finished PDU will be awaited, for example one generated using
//!    [spacepackets::cfdp::pdu::finished::FinishedPduCreator].
//! 6. A finished PDU ACK packet will be generated to be sent to the remote CFDP entity.
//!    The [spacepackets::cfdp::pdu::finished::FinishedPduReader] can be used to inspect the
//!    generated PDU.
use core::{
    cell::{Cell, RefCell},
    ops::ControlFlow,
    str::Utf8Error,
};

use spacepackets::{
    ByteConversionError,
    cfdp::{
        ConditionCode, Direction, FaultHandlerCode, LargeFileFlag, PduType, SegmentMetadataFlag,
        SegmentationControl, TransactionStatus, TransmissionMode,
        lv::Lv,
        pdu::{
            CfdpPdu, CommonPduConfig, FileDirectiveType, PduError, PduHeader, WritablePduPacket,
            ack::AckPdu,
            eof::EofPdu,
            file_data::{
                FileDataPduCreatorWithReservedDatafield,
                calculate_max_file_seg_len_for_max_packet_len_and_pdu_header,
            },
            finished::{DeliveryCode, FileStatus, FinishedPduReader},
            metadata::{MetadataGenericParams, MetadataPduCreator},
            nak::NakPduReader,
        },
    },
    util::{UnsignedByteField, UnsignedEnum},
};

use spacepackets::seq_count::SequenceCounter;

use crate::{
    DummyPduProvider, EntityType, FaultInfo, GenericSendError, PduProvider, PositiveAckParams,
    TimerCreator, time::Countdown,
};

use super::{
    LocalEntityConfig, PacketTarget, PduSender, RemoteConfigStore, RemoteEntityConfig, State,
    TransactionId, UserFaultHook,
    filestore::{FilestoreError, VirtualFilestore},
    request::{ReadablePutRequest, StaticPutRequestCacher},
    user::{CfdpUser, TransactionFinishedParams},
};

/// This enumeration models the different transaction steps of the source entity handler.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TransactionStep {
    Idle = 0,
    TransactionStart = 1,
    SendingMetadata = 3,
    SendingFileData = 4,
    /// Re-transmitting missing packets in acknowledged mode
    Retransmitting = 5,
    SendingEof = 6,
    WaitingForEofAck = 7,
    WaitingForFinished = 8,
    NoticeOfCompletion = 10,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct FileParams {
    pub progress: u64,
    pub segment_len: u64,
    pub crc32: u32,
    pub metadata_only: bool,
    pub file_size: u64,
    pub empty_file: bool,
    /// The checksum is cached to avoid expensive re-calculation when the EOF PDU needs to be
    /// re-sent.
    pub checksum_completed_file: Option<u32>,
}

// Explicit choice to put all simple internal fields into Cells.
// I think this is more efficient than wrapping the whole helper into a RefCell, especially
// because some of the individual fields are used frequently.
struct StateHelper {
    step: Cell<TransactionStep>,
    state: Cell<super::State>,
    num_packets_ready: Cell<u32>,
}

impl Default for StateHelper {
    fn default() -> Self {
        Self {
            state: Cell::new(super::State::Idle),
            step: Cell::new(TransactionStep::Idle),
            num_packets_ready: Cell::new(0),
        }
    }
}

impl StateHelper {
    #[allow(dead_code)]
    pub fn reset(&self) {
        self.step.set(TransactionStep::Idle);
        self.state.set(super::State::Idle);
        self.num_packets_ready.set(0);
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FinishedParams {
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("can not process packet type {pdu_type:?} with directive type {directive_type:?}")]
    CantProcessPacketType {
        pdu_type: PduType,
        directive_type: Option<FileDirectiveType>,
    },
    #[error("unexpected PDU")]
    UnexpectedPdu {
        pdu_type: PduType,
        directive_type: Option<FileDirectiveType>,
    },
    #[error("source handler is already busy with put request")]
    PutRequestAlreadyActive,
    #[error("error caching put request")]
    PutRequestCaching(ByteConversionError),
    #[error("filestore error: {0}")]
    FilestoreError(#[from] FilestoreError),
    #[error("source file does not have valid UTF8 format: {0}")]
    SourceFileNotValidUtf8(Utf8Error),
    #[error("destination file does not have valid UTF8 format: {0}")]
    DestFileNotValidUtf8(Utf8Error),
    #[error("invalid NAK PDU received")]
    InvalidNakPdu,
    #[error("error related to PDU creation: {0}")]
    Pdu(#[from] PduError),
    #[error("cfdp feature not implemented")]
    NotImplemented,
    #[error("issue sending PDU: {0}")]
    SendError(#[from] GenericSendError),
}

#[derive(Debug, thiserror::Error)]
pub enum PutRequestError {
    #[error("error caching put request: {0}")]
    Storage(#[from] ByteConversionError),
    #[error("already busy with put request")]
    AlreadyBusy,
    #[error("no remote entity configuration found for {0:?}")]
    NoRemoteCfgFound(UnsignedByteField),
    #[error("source file does not have valid UTF8 format: {0}")]
    SourceFileNotValidUtf8(#[from] Utf8Error),
    #[error("source file does not exist")]
    FileDoesNotExist,
    #[error("filestore error: {0}")]
    FilestoreError(#[from] FilestoreError),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AnomalyTracker {
    invalid_ack_directive_code: u8,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum FsmContext {
    #[default]
    None,
    ResetWhenPossible,
}

#[derive(Debug)]
pub struct TransactionParams<CountdownInstance: Countdown> {
    transaction_id: Option<TransactionId>,
    remote_cfg: Option<RemoteEntityConfig>,
    transmission_mode: Option<super::TransmissionMode>,
    closure_requested: bool,
    cond_code_eof: Cell<Option<ConditionCode>>,
    finished_params: Option<FinishedParams>,
    // File specific transfer fields
    file_params: FileParams,
    // PDU configuration is cached so it can be re-used for all PDUs generated for file transfers.
    pdu_conf: CommonPduConfig,
    check_timer: Option<CountdownInstance>,
    positive_ack_params: Cell<Option<PositiveAckParams>>,
    ack_timer: RefCell<Option<CountdownInstance>>,
}

impl<CountdownInstance: Countdown> Default for TransactionParams<CountdownInstance> {
    fn default() -> Self {
        Self {
            transaction_id: Default::default(),
            remote_cfg: Default::default(),
            transmission_mode: Default::default(),
            closure_requested: Default::default(),
            cond_code_eof: Default::default(),
            finished_params: Default::default(),
            file_params: Default::default(),
            pdu_conf: Default::default(),
            check_timer: Default::default(),
            positive_ack_params: Default::default(),
            ack_timer: Default::default(),
        }
    }
}

impl<CountdownInstance: Countdown> TransactionParams<CountdownInstance> {
    #[inline]
    fn reset(&mut self) {
        self.transaction_id = None;
        self.transmission_mode = None;
    }
}

/// This is the primary CFDP source handler. It models the CFDP source entity, which is
/// primarily responsible for handling put requests to send files to another CFDP destination
/// entity.
///
/// As such, it contains a state machine to perform all operations necessary to perform a
/// source-to-destination file transfer. This class uses the user provides [PduSender] to
/// send the CFDP PDU packets generated by the state machine.
///
/// The following core functions are the primary interface:
///
/// 1. [Self::put_request] can be used to start transactions, most notably to start
///    and perform a Copy File procedure to send a file or to send a Proxy Put Request to request
///    a file.
/// 2. [Self::state_machine] is the primary interface to execute an
///    active file transfer. It generates the necessary CFDP PDUs for this process.
///    This method is also used to insert received packets with the appropriate destination ID
///    and target handler type into the state machine.
///
/// A put request will only be accepted if the handler is in the idle state.
///
/// The handler requires the [alloc] feature but will allocated all required memory on construction
/// time. This means that the handler is still suitable for embedded systems where run-time
/// allocation is prohibited. Furthermore, it uses the [VirtualFilestore] abstraction to allow
/// usage on systems without a [std] filesystem.
/// This handler does not support concurrency out of the box. Instead, if concurrent handling
/// is required, it is recommended to create a new handler and run all active handlers inside a
/// thread pool, or move the newly created handler to a new thread.
pub struct SourceHandler<
    PduSenderInstance: PduSender,
    UserFaultHookInstance: UserFaultHook,
    Vfs: VirtualFilestore,
    RemoteConfigStoreInstance: RemoteConfigStore,
    TimerCreatorInstance: TimerCreator<Countdown = CountdownInstance>,
    CountdownInstance: Countdown,
    SequenceCounterInstance: SequenceCounter,
> {
    local_cfg: LocalEntityConfig<UserFaultHookInstance>,
    pdu_sender: PduSenderInstance,
    pdu_and_cksum_buffer: RefCell<alloc::vec::Vec<u8>>,
    put_request_cacher: StaticPutRequestCacher,
    remote_cfg_table: RemoteConfigStoreInstance,
    vfs: Vfs,
    state_helper: StateHelper,
    transaction_params: TransactionParams<CountdownInstance>,
    timer_creator: TimerCreatorInstance,
    seq_count_provider: SequenceCounterInstance,
    anomalies: AnomalyTracker,
}

impl<
    PduSenderInstance: PduSender,
    UserFaultHookInstance: UserFaultHook,
    Vfs: VirtualFilestore,
    RemoteConfigStoreInstance: RemoteConfigStore,
    TimerCreatorInstance: TimerCreator<Countdown = CountdownInstance>,
    CountdownInstance: Countdown,
    SequenceCounterInstance: SequenceCounter,
>
    SourceHandler<
        PduSenderInstance,
        UserFaultHookInstance,
        Vfs,
        RemoteConfigStoreInstance,
        TimerCreatorInstance,
        CountdownInstance,
        SequenceCounterInstance,
    >
{
    /// Creates a new instance of a source handler.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The local entity configuration for this source handler.
    /// * `pdu_sender` - [PduSender] used to send CFDP PDUs generated by the handler.
    /// * `vfs` - [VirtualFilestore] implementation used by the handler, which decouples the CFDP
    ///   implementation from the underlying filestore/filesystem. This allows to use this handler
    ///   for embedded systems where a standard runtime might not be available.
    /// * `put_request_cacher` - The put request cacher is used cache put requests without
    ///   requiring run-time allocation.
    /// * `pdu_and_cksum_buf_size` - The handler requires a buffer to generate PDUs and perform
    ///   checksum calculations. The user can specify the size of this buffer, so this should be
    ///   set to the maximum expected PDU size or a conservative upper bound for this size, for
    ///   example 2048 or 4096 bytes.
    /// * `remote_cfg_table` - The [RemoteEntityConfig] used to look up remote
    ///   entities and target specific configuration for file copy operations.
    /// * `timer_creator` - [TimerCreator] used by the CFDP handler to generate
    ///   timers required by various tasks. This allows to use this handler for embedded systems
    ///   where the standard time APIs might not be available.
    /// * `seq_count_provider` - The [SequenceCounter] used to generate the [TransactionId]
    ///   which contains an incrementing counter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: LocalEntityConfig<UserFaultHookInstance>,
        pdu_sender: PduSenderInstance,
        vfs: Vfs,
        put_request_cacher: StaticPutRequestCacher,
        pdu_and_cksum_buf_size: usize,
        remote_cfg_table: RemoteConfigStoreInstance,
        timer_creator: TimerCreatorInstance,
        seq_count_provider: SequenceCounterInstance,
    ) -> Self {
        Self {
            local_cfg: cfg,
            remote_cfg_table,
            pdu_sender,
            pdu_and_cksum_buffer: RefCell::new(alloc::vec![0; pdu_and_cksum_buf_size]),
            vfs,
            put_request_cacher,
            state_helper: Default::default(),
            transaction_params: Default::default(),
            anomalies: Default::default(),
            timer_creator,
            seq_count_provider,
        }
    }

    /// Calls [Self::state_machine], without inserting a packet.
    pub fn state_machine_no_packet(
        &mut self,
        cfdp_user: &mut impl CfdpUser,
    ) -> Result<u32, SourceError> {
        self.state_machine(cfdp_user, None::<&DummyPduProvider>)
    }

    /// This is the core function to drive the source handler. It is also used to insert
    /// packets into the source handler.
    ///
    /// The state machine should either be called if a packet with the appropriate destination ID
    /// is received, or periodically in IDLE periods to perform all CFDP related tasks, for example
    /// checking for timeouts or missed file segments.
    ///
    /// The function returns the number of sent PDU packets on success.
    pub fn state_machine(
        &mut self,
        cfdp_user: &mut impl CfdpUser,
        pdu: Option<&impl PduProvider>,
    ) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        if let Some(packet) = pdu {
            sent_packets += self.insert_packet(cfdp_user, packet)?;
        }
        match self.state() {
            super::State::Idle => {
                // TODO: In acknowledged mode, add timer handling.
                Ok(0)
            }
            super::State::Busy => {
                sent_packets += self.fsm_busy(cfdp_user, pdu)?;
                Ok(sent_packets)
            }
            super::State::Suspended => {
                // There is now way to suspend the handler currently anyway.
                Ok(0)
            }
        }
    }

    #[inline]
    pub fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction_params.transaction_id
    }

    /// Returns the [TransmissionMode] for the active file operation.
    #[inline]
    pub fn transmission_mode(&self) -> Option<super::TransmissionMode> {
        self.transaction_params.transmission_mode
    }

    /// Get the [TransactionStep], which denotes the exact step of a pending CFDP transaction when
    /// applicable.
    #[inline]
    pub fn step(&self) -> TransactionStep {
        self.state_helper.step.get()
    }

    #[inline]
    pub fn state(&self) -> State {
        self.state_helper.state.get()
    }

    #[inline]
    pub fn local_cfg(&self) -> &LocalEntityConfig<UserFaultHookInstance> {
        &self.local_cfg
    }

    /// This function is used to pass a put request to the source handler, which is
    /// also used to start a file copy operation. As such, this function models the Put.request
    /// CFDP primtiive.
    ///
    /// Please note that the source handler can also process one put request at a time.
    /// The caller is responsible of creating a new source handler, one handler can only handle
    /// one file copy request at a time.
    pub fn put_request(
        &mut self,
        put_request: &impl ReadablePutRequest,
    ) -> Result<(), PutRequestError> {
        if self.state() != super::State::Idle {
            return Err(PutRequestError::AlreadyBusy);
        }
        self.put_request_cacher.set(put_request)?;
        let remote_cfg = self.remote_cfg_table.get(
            self.put_request_cacher
                .static_fields
                .destination_id
                .value_const(),
        );
        if remote_cfg.is_none() {
            return Err(PutRequestError::NoRemoteCfgFound(
                self.put_request_cacher.static_fields.destination_id,
            ));
        }
        let remote_cfg = remote_cfg.unwrap();
        self.state_helper.num_packets_ready.set(0);
        let transmission_mode = if self.put_request_cacher.static_fields.trans_mode.is_some() {
            self.put_request_cacher.static_fields.trans_mode.unwrap()
        } else {
            remote_cfg.default_transmission_mode
        };
        let closure_requested = if self
            .put_request_cacher
            .static_fields
            .closure_requested
            .is_some()
        {
            self.put_request_cacher
                .static_fields
                .closure_requested
                .unwrap()
        } else {
            remote_cfg.closure_requested_by_default
        };
        if self.put_request_cacher.has_source_file()
            && !self.vfs.exists(self.put_request_cacher.source_file()?)?
        {
            return Err(PutRequestError::FileDoesNotExist);
        }

        let transaction_id = TransactionId::new(
            self.local_cfg().id,
            UnsignedByteField::new(
                SequenceCounterInstance::MAX_BIT_WIDTH / 8,
                self.seq_count_provider.get_and_increment().into(),
            ),
        );
        // Both the source entity and destination entity ID field must have the same size.
        // We use the larger of either the Put Request destination ID or the local entity ID
        // as the size for the new entity IDs.
        let larger_entity_width = core::cmp::max(
            self.local_cfg.id.size(),
            self.put_request_cacher.static_fields.destination_id.size(),
        );
        let create_id = |cached_id: &UnsignedByteField| {
            if larger_entity_width != cached_id.size() {
                UnsignedByteField::new(larger_entity_width, cached_id.value_const())
            } else {
                *cached_id
            }
        };

        // Set PDU configuration fields which are important for generating PDUs.
        self.transaction_params
            .pdu_conf
            .set_source_and_dest_id(
                create_id(&self.local_cfg.id),
                create_id(&self.put_request_cacher.static_fields.destination_id),
            )
            .unwrap();
        // Set up other PDU configuration fields.
        self.transaction_params.pdu_conf.direction = Direction::TowardsReceiver;
        self.transaction_params.pdu_conf.crc_flag =
            remote_cfg.crc_on_transmission_by_default.into();
        self.transaction_params.pdu_conf.transaction_seq_num = *transaction_id.seq_num();
        self.transaction_params.pdu_conf.trans_mode = transmission_mode;
        self.transaction_params.file_params.segment_len =
            self.calculate_max_file_seg_len(remote_cfg);

        self.transaction_params.transaction_id = Some(transaction_id);
        self.transaction_params.remote_cfg = Some(*remote_cfg);
        self.transaction_params.transmission_mode = Some(transmission_mode);
        self.transaction_params.closure_requested = closure_requested;
        self.transaction_params.cond_code_eof.set(None);
        self.transaction_params.finished_params = None;

        self.state_helper.state.set(super::State::Busy);
        Ok(())
    }

    fn insert_packet(
        &mut self,
        _cfdp_user: &mut impl CfdpUser,
        packet_to_insert: &impl PduProvider,
    ) -> Result<u32, SourceError> {
        if packet_to_insert.packet_target()? != PacketTarget::SourceEntity {
            // Unwrap is okay here, a PacketInfo for a file data PDU should always have the
            // destination as the target.
            return Err(SourceError::CantProcessPacketType {
                pdu_type: packet_to_insert.pdu_type(),
                directive_type: packet_to_insert.file_directive_type(),
            });
        }
        if packet_to_insert.pdu_type() == PduType::FileData {
            // The [PacketInfo] API should ensure that file data PDUs can not be passed
            // into a source entity, so this should never happen.
            return Err(SourceError::UnexpectedPdu {
                pdu_type: PduType::FileData,
                directive_type: None,
            });
        }
        let mut sent_packets = 0;

        // Unwrap is okay here, the [PacketInfo] API should ensure that the directive type is
        // always a valid value.
        match packet_to_insert
            .file_directive_type()
            .expect("PDU directive type unexpectedly not set")
        {
            FileDirectiveType::FinishedPdu => {
                let finished_pdu = FinishedPduReader::new(packet_to_insert.raw_pdu())?;
                self.handle_finished_pdu(&finished_pdu)?
            }
            FileDirectiveType::NakPdu => {
                let nak_pdu = NakPduReader::new(packet_to_insert.raw_pdu())?;
                sent_packets += self.handle_nak_pdu(&nak_pdu)?;
            }
            FileDirectiveType::KeepAlivePdu => self.handle_keep_alive_pdu(),
            FileDirectiveType::AckPdu => {
                let ack_pdu = AckPdu::from_bytes(packet_to_insert.raw_pdu())?;
                self.handle_ack_pdu(&ack_pdu)?
            }
            FileDirectiveType::EofPdu
            | FileDirectiveType::PromptPdu
            | FileDirectiveType::MetadataPdu => {
                return Err(SourceError::CantProcessPacketType {
                    pdu_type: packet_to_insert.pdu_type(),
                    directive_type: packet_to_insert.file_directive_type(),
                });
            }
        }
        Ok(sent_packets)
    }

    /// This functions models the Cancel.request CFDP primitive and is the recommended way to
    /// cancel a transaction.
    ///
    /// This method will cause a Notice of Cancellation at this entity if a transaction is active
    /// and the passed transaction ID matches the currently active transaction ID. Please note
    /// that the state machine might still be active because a cancelled transfer might still
    /// require some packets to be sent to the remote receiver entity.
    ///
    /// If not unexpected errors occur, this method returns [true] if the transfer was cancelled
    /// propery and [false] if there is no transaction active or the passed transaction ID and the
    /// active ID do not match.
    pub fn cancel_request(
        &mut self,
        user: &mut impl CfdpUser,
        transaction_id: &TransactionId,
    ) -> Result<bool, SourceError> {
        if self.state() == super::State::Idle {
            return Ok(false);
        }
        if let Some(active_id) = self.transaction_id() {
            if active_id == *transaction_id {
                // Control flow result can be ignored here for the cancel request.
                self.notice_of_cancellation(user, ConditionCode::CancelRequestReceived)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// This function is public to allow completely resetting the handler, but it is explicitely
    /// discouraged to do this. CFDP has mechanism to detect issues and errors on itself.
    /// Resetting the handler might interfere with these mechanisms and lead to unexpected
    /// behaviour.
    pub fn reset(&mut self) {
        self.state_helper = Default::default();
        self.transaction_params.reset();
    }

    #[inline]
    fn set_step(&mut self, step: TransactionStep) {
        self.set_step_internal(step);
    }

    #[inline]
    fn set_step_internal(&self, step: TransactionStep) {
        self.state_helper.step.set(step);
    }

    fn fsm_busy(
        &mut self,
        user: &mut impl CfdpUser,
        _pdu: Option<&impl PduProvider>,
    ) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        if self.step() == TransactionStep::Idle {
            self.set_step(TransactionStep::TransactionStart);
        }
        if self.step() == TransactionStep::TransactionStart {
            self.handle_transaction_start(user)?;
            self.set_step(TransactionStep::SendingMetadata);
        }
        if self.step() == TransactionStep::SendingMetadata {
            self.prepare_and_send_metadata_pdu()?;
            self.set_step(TransactionStep::SendingFileData);
            sent_packets += 1;
        }
        if self.step() == TransactionStep::SendingFileData {
            if let ControlFlow::Break(packets) = self.file_data_fsm()? {
                sent_packets += packets;
                // Exit for each file data PDU to allow flow control.
                return Ok(sent_packets);
            }
        }
        if self.step() == TransactionStep::SendingEof {
            self.eof_fsm(user)?;
            sent_packets += 1;
        }
        if self.step() == TransactionStep::WaitingForEofAck {
            sent_packets += self.handle_waiting_for_ack_pdu(user)?;
        }
        if self.step() == TransactionStep::WaitingForFinished {
            sent_packets += self.handle_waiting_for_finished_pdu(user)?;
        }
        if self.step() == TransactionStep::NoticeOfCompletion {
            self.notice_of_completion(user);
            self.reset();
        }
        Ok(sent_packets)
    }

    fn handle_waiting_for_ack_pdu(&mut self, user: &mut impl CfdpUser) -> Result<u32, SourceError> {
        self.handle_positive_ack_procedures(user)
    }

    fn handle_positive_ack_procedures(
        &mut self,
        user: &mut impl CfdpUser,
    ) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        let current_params = self.transaction_params.positive_ack_params.get();
        if let Some(mut positive_ack_params) = current_params {
            if self
                .transaction_params
                .ack_timer
                .borrow_mut()
                .as_ref()
                .unwrap()
                .has_expired()
            {
                let ack_timer_exp_limit = self
                    .transaction_params
                    .remote_cfg
                    .as_ref()
                    .unwrap()
                    .positive_ack_timer_expiration_limit;
                if positive_ack_params.ack_counter + 1 >= ack_timer_exp_limit {
                    let (fault_packets_sent, ctx) =
                        self.declare_fault(user, ConditionCode::PositiveAckLimitReached)?;
                    sent_packets += fault_packets_sent;
                    if ctx == FsmContext::ResetWhenPossible {
                        self.reset();
                    } else {
                        positive_ack_params.ack_counter = 0;
                        positive_ack_params.positive_ack_of_cancellation = true;
                    }
                } else {
                    self.transaction_params
                        .ack_timer
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .reset();
                    positive_ack_params.ack_counter += 1;
                    self.prepare_and_send_eof_pdu(
                        user,
                        self.transaction_params
                            .file_params
                            .checksum_completed_file
                            .unwrap(),
                    )?;
                    sent_packets += 1;
                }
            }

            self.transaction_params
                .positive_ack_params
                .set(Some(positive_ack_params));
        }
        Ok(sent_packets)
    }

    fn handle_retransmission(&mut self, nak_pdu: &NakPduReader) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        let segment_req_iter = nak_pdu.get_segment_requests_iterator().unwrap();
        for segment_req in segment_req_iter {
            // Special case: Metadata PDU is re-requested.
            if segment_req.0 == 0 && segment_req.1 == 0 {
                self.prepare_and_send_metadata_pdu()?;
                sent_packets += 1;
                continue;
            } else {
                if (segment_req.1 < segment_req.0)
                    || (segment_req.0 > self.transaction_params.file_params.progress)
                {
                    return Err(SourceError::InvalidNakPdu);
                }
                let mut missing_chunk_len = segment_req.1 - segment_req.0;
                let current_offset = segment_req.0;
                while missing_chunk_len > 0 {
                    let chunk_size = core::cmp::min(
                        missing_chunk_len,
                        self.transaction_params.file_params.segment_len,
                    );
                    self.prepare_and_send_file_data_pdu(current_offset, chunk_size)?;
                    sent_packets += 1;
                    missing_chunk_len -= missing_chunk_len;
                }
            }
        }
        Ok(sent_packets)
    }

    fn handle_waiting_for_finished_pdu(
        &mut self,
        user: &mut impl CfdpUser,
    ) -> Result<u32, SourceError> {
        // If we reach this state, countdown definitely is set.
        #[allow(clippy::collapsible_if)]
        if self.transmission_mode().unwrap() == TransmissionMode::Unacknowledged
            && self
                .transaction_params
                .check_timer
                .as_ref()
                .unwrap()
                .has_expired()
        {
            let (sent_packets, ctx) = self.declare_fault(user, ConditionCode::CheckLimitReached)?;
            if ctx == FsmContext::ResetWhenPossible {
                self.reset();
            }
            return Ok(sent_packets);
        }
        Ok(0)
    }

    fn eof_fsm(&mut self, user: &mut impl CfdpUser) -> Result<(), SourceError> {
        let checksum = self.vfs.calculate_checksum(
            self.put_request_cacher.source_file().unwrap(),
            self.transaction_params
                .remote_cfg
                .as_ref()
                .unwrap()
                .default_crc_type,
            self.transaction_params.file_params.file_size,
            &mut self.pdu_and_cksum_buffer.borrow_mut(),
        )?;
        self.transaction_params.file_params.checksum_completed_file = Some(checksum);
        self.prepare_and_send_eof_pdu(user, checksum)?;
        if self.transmission_mode().unwrap() == TransmissionMode::Unacknowledged {
            if self.transaction_params.closure_requested {
                self.transaction_params.check_timer = Some(
                    self.timer_creator
                        .create_countdown(crate::TimerContext::CheckLimit {
                            local_id: self.local_cfg.id,
                            remote_id: self
                                .transaction_params
                                .remote_cfg
                                .as_ref()
                                .unwrap()
                                .entity_id,
                            entity_type: EntityType::Sending,
                        }),
                );
                self.set_step(TransactionStep::WaitingForFinished);
            } else {
                self.set_step(TransactionStep::NoticeOfCompletion);
            }
        } else {
            self.start_positive_ack_procedure();
        }
        Ok(())
    }

    fn start_positive_ack_procedure(&self) {
        self.set_step_internal(TransactionStep::WaitingForEofAck);
        match self.transaction_params.positive_ack_params.get() {
            Some(mut current) => {
                current.ack_counter = 0;
                self.transaction_params
                    .positive_ack_params
                    .set(Some(current));
            }
            None => self
                .transaction_params
                .positive_ack_params
                .set(Some(PositiveAckParams {
                    ack_counter: 0,
                    positive_ack_of_cancellation: false,
                })),
        }

        *self.transaction_params.ack_timer.borrow_mut() = Some(
            self.timer_creator
                .create_countdown(crate::TimerContext::PositiveAck {
                    expiry_time: self
                        .transaction_params
                        .remote_cfg
                        .as_ref()
                        .unwrap()
                        .positive_ack_timer_interval,
                }),
        );
    }

    fn handle_transaction_start(
        &mut self,
        cfdp_user: &mut impl CfdpUser,
    ) -> Result<(), SourceError> {
        if !self.put_request_cacher.has_source_file() {
            self.transaction_params.file_params.metadata_only = true;
        } else {
            let source_file = self
                .put_request_cacher
                .source_file()
                .map_err(SourceError::SourceFileNotValidUtf8)?;
            if !self.vfs.exists(source_file)? {
                return Err(SourceError::FilestoreError(
                    FilestoreError::FileDoesNotExist,
                ));
            }
            // We expect the destination file path to consist of valid UTF-8 characters as well.
            self.put_request_cacher
                .dest_file()
                .map_err(SourceError::DestFileNotValidUtf8)?;
            self.transaction_params.file_params.file_size = self.vfs.file_size(source_file)?;
            if self.transaction_params.file_params.file_size > u32::MAX as u64 {
                self.transaction_params.pdu_conf.file_flag = LargeFileFlag::Large
            } else {
                if self.transaction_params.file_params.file_size == 0 {
                    self.transaction_params.file_params.empty_file = true;
                }
                self.transaction_params.pdu_conf.file_flag = LargeFileFlag::Normal
            }
        }
        cfdp_user.transaction_indication(&self.transaction_id().unwrap());
        Ok(())
    }

    fn prepare_and_send_ack_pdu(
        &mut self,
        condition_code: ConditionCode,
        transaction_status: TransactionStatus,
    ) -> Result<(), SourceError> {
        let ack_pdu = AckPdu::new(
            PduHeader::new_for_file_directive(self.transaction_params.pdu_conf, 0),
            FileDirectiveType::FinishedPdu,
            condition_code,
            transaction_status,
        )
        .map_err(PduError::from)?;
        self.pdu_send_helper(&ack_pdu)?;
        Ok(())
    }

    fn prepare_and_send_metadata_pdu(&mut self) -> Result<(), SourceError> {
        let metadata_params = MetadataGenericParams::new(
            self.transaction_params.closure_requested,
            self.transaction_params
                .remote_cfg
                .as_ref()
                .unwrap()
                .default_crc_type,
            self.transaction_params.file_params.file_size,
        );
        if self.transaction_params.file_params.metadata_only {
            let metadata_pdu = MetadataPduCreator::new(
                PduHeader::new_for_file_directive(self.transaction_params.pdu_conf, 0),
                metadata_params,
                Lv::new_empty(),
                Lv::new_empty(),
                self.put_request_cacher.opts_slice(),
            );
            return self.pdu_send_helper(&metadata_pdu);
        }
        let metadata_pdu = MetadataPduCreator::new(
            PduHeader::new_for_file_directive(self.transaction_params.pdu_conf, 0),
            metadata_params,
            Lv::new_from_str(self.put_request_cacher.source_file().unwrap()).unwrap(),
            Lv::new_from_str(self.put_request_cacher.dest_file().unwrap()).unwrap(),
            self.put_request_cacher.opts_slice(),
        );
        self.pdu_send_helper(&metadata_pdu)
    }

    fn file_data_fsm(&mut self) -> Result<ControlFlow<u32>, SourceError> {
        if !self.transaction_params.file_params.metadata_only
            && self.transaction_params.file_params.progress
                < self.transaction_params.file_params.file_size
            && self.send_progressing_file_data_pdu()?
        {
            return Ok(ControlFlow::Break(1));
        }
        if self.transaction_params.file_params.empty_file
            || self.transaction_params.file_params.progress
                >= self.transaction_params.file_params.file_size
        {
            // EOF is still expected.
            self.set_step(TransactionStep::SendingEof);
            self.transaction_params
                .cond_code_eof
                .set(Some(ConditionCode::NoError));
        } else if self.transaction_params.file_params.metadata_only {
            // Special case: Metadata Only, no EOF required.
            if self.transaction_params.closure_requested {
                self.set_step(TransactionStep::WaitingForFinished);
            } else {
                self.set_step(TransactionStep::NoticeOfCompletion);
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    fn notice_of_completion(&mut self, cfdp_user: &mut impl CfdpUser) {
        if self.local_cfg.indication_cfg.transaction_finished {
            // The first case happens for unacknowledged file copy operation with no closure.
            let finished_params = match self.transaction_params.finished_params {
                Some(finished_params) => TransactionFinishedParams {
                    id: self.transaction_id().unwrap(),
                    condition_code: finished_params.condition_code,
                    delivery_code: finished_params.delivery_code,
                    file_status: finished_params.file_status,
                },
                None => TransactionFinishedParams {
                    id: self.transaction_id().unwrap(),
                    condition_code: ConditionCode::NoError,
                    delivery_code: DeliveryCode::Complete,
                    file_status: FileStatus::Unreported,
                },
            };
            cfdp_user.transaction_finished_indication(&finished_params);
        }
    }

    fn calculate_max_file_seg_len(&self, remote_cfg: &RemoteEntityConfig) -> u64 {
        let mut derived_max_seg_len = calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(
            &PduHeader::new_for_file_directive(self.transaction_params.pdu_conf, 0),
            remote_cfg.max_packet_len,
            None,
        );
        if remote_cfg.max_file_segment_len.is_some() {
            derived_max_seg_len = core::cmp::min(
                remote_cfg.max_file_segment_len.unwrap(),
                derived_max_seg_len,
            );
        }
        derived_max_seg_len as u64
    }

    fn send_progressing_file_data_pdu(&mut self) -> Result<bool, SourceError> {
        // Should never be called, but use defensive programming here.
        if self.transaction_params.file_params.progress
            >= self.transaction_params.file_params.file_size
        {
            return Ok(false);
        }
        let read_len = self.transaction_params.file_params.segment_len.min(
            self.transaction_params.file_params.file_size
                - self.transaction_params.file_params.progress,
        );
        self.prepare_and_send_file_data_pdu(
            self.transaction_params.file_params.progress,
            read_len,
        )?;
        Ok(true)
    }

    fn prepare_and_send_file_data_pdu(
        &mut self,
        offset: u64,
        size: u64,
    ) -> Result<(), SourceError> {
        let pdu_creator = FileDataPduCreatorWithReservedDatafield::new_no_seg_metadata(
            PduHeader::new_for_file_data(
                self.transaction_params.pdu_conf,
                0,
                SegmentMetadataFlag::NotPresent,
                SegmentationControl::NoRecordBoundaryPreservation,
            ),
            offset,
            size,
        );
        let mut unwritten_pdu =
            pdu_creator.write_to_bytes_partially(self.pdu_and_cksum_buffer.get_mut())?;
        self.vfs.read_data(
            self.put_request_cacher.source_file().unwrap(),
            offset,
            size,
            unwritten_pdu.file_data_field_mut(),
        )?;
        let written_len = unwritten_pdu.finish();
        self.pdu_sender.send_pdu(
            PduType::FileData,
            None,
            &self.pdu_and_cksum_buffer.borrow()[0..written_len],
        )?;
        self.transaction_params.file_params.progress += size;
        Ok(())
    }

    fn prepare_and_send_eof_pdu(
        &self,
        cfdp_user: &mut impl CfdpUser,
        checksum: u32,
    ) -> Result<(), SourceError> {
        let eof_pdu = EofPdu::new(
            PduHeader::new_for_file_directive(self.transaction_params.pdu_conf, 0),
            self.transaction_params
                .cond_code_eof
                .get()
                .unwrap_or(ConditionCode::NoError),
            checksum,
            self.transaction_params.file_params.progress,
            None,
        );
        self.pdu_send_helper(&eof_pdu)?;
        if self.local_cfg.indication_cfg.eof_sent {
            cfdp_user.eof_sent_indication(&self.transaction_id().unwrap());
        }
        Ok(())
    }

    fn pdu_send_helper(&self, pdu: &(impl WritablePduPacket + CfdpPdu)) -> Result<(), SourceError> {
        let mut pdu_buffer_mut = self.pdu_and_cksum_buffer.borrow_mut();
        let written_len = pdu.write_to_bytes(&mut pdu_buffer_mut)?;
        self.pdu_sender.send_pdu(
            pdu.pdu_type(),
            pdu.file_directive_type(),
            &pdu_buffer_mut[0..written_len],
        )?;
        Ok(())
    }

    fn handle_finished_pdu(&mut self, finished_pdu: &FinishedPduReader) -> Result<(), SourceError> {
        // Ignore this packet when we are idle.
        if self.state() == State::Idle {
            return Ok(());
        }
        if self.step() != TransactionStep::WaitingForFinished {
            return Err(SourceError::UnexpectedPdu {
                pdu_type: PduType::FileDirective,
                directive_type: Some(FileDirectiveType::FinishedPdu),
            });
        }
        // Unwrapping should be fine here, the transfer state is valid when we are not in IDLE
        // mode.
        self.transaction_params.finished_params = Some(FinishedParams {
            condition_code: finished_pdu.condition_code(),
            delivery_code: finished_pdu.delivery_code(),
            file_status: finished_pdu.file_status(),
        });
        if let Some(TransmissionMode::Acknowledged) = self.transmission_mode() {
            self.prepare_and_send_ack_pdu(
                finished_pdu.condition_code(),
                TransactionStatus::Active,
            )?;
        }
        self.set_step(TransactionStep::NoticeOfCompletion);
        Ok(())
    }

    fn handle_nak_pdu(&mut self, nak_pdu: &NakPduReader) -> Result<u32, SourceError> {
        self.handle_retransmission(nak_pdu)
    }

    fn handle_ack_pdu(&mut self, ack_pdu: &AckPdu) -> Result<(), SourceError> {
        if self.step() != TransactionStep::WaitingForEofAck {
            // Drop the packet, wrong state to handle it..
            return Err(SourceError::UnexpectedPdu {
                pdu_type: PduType::FileDirective,
                directive_type: Some(FileDirectiveType::AckPdu),
            });
        }
        if ack_pdu.directive_code_of_acked_pdu() == FileDirectiveType::EofPdu {
            self.set_step(TransactionStep::WaitingForFinished);
        } else {
            self.anomalies.invalid_ack_directive_code =
                self.anomalies.invalid_ack_directive_code.wrapping_add(1);
        }
        Ok(())
    }

    pub fn notice_of_cancellation(
        &mut self,
        user: &mut impl CfdpUser,
        condition_code: ConditionCode,
    ) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        let ctx = self.notice_of_cancellation_internal(user, condition_code, &mut sent_packets)?;
        if ctx == FsmContext::ResetWhenPossible {
            self.reset();
        }
        Ok(sent_packets)
    }

    fn notice_of_cancellation_internal(
        &self,
        user: &mut impl CfdpUser,
        condition_code: ConditionCode,
        sent_packets: &mut u32,
    ) -> Result<FsmContext, SourceError> {
        self.transaction_params
            .cond_code_eof
            .set(Some(condition_code));
        // As specified in 4.11.2.2, prepare an EOF PDU to be sent to the remote entity. Supply
        // the checksum for the file copy progress sent so far.
        let checksum = self.vfs.calculate_checksum(
            self.put_request_cacher.source_file().unwrap(),
            self.transaction_params
                .remote_cfg
                .as_ref()
                .unwrap()
                .default_crc_type,
            self.transaction_params.file_params.progress,
            &mut self.pdu_and_cksum_buffer.borrow_mut(),
        )?;
        self.prepare_and_send_eof_pdu(user, checksum)?;
        *sent_packets += 1;
        if self.transmission_mode().unwrap() == TransmissionMode::Unacknowledged {
            // We are done.
            Ok(FsmContext::ResetWhenPossible)
        } else {
            self.start_positive_ack_procedure();
            Ok(FsmContext::default())
        }
    }

    pub fn notice_of_suspension(&mut self) {
        self.notice_of_suspension_internal();
    }

    fn notice_of_suspension_internal(&self) {}

    pub fn abandon_transaction(&mut self) {
        // I guess an abandoned transaction just stops whatever the handler is doing and resets
        // it to a clean state.. The implementation for this is quite easy.
        self.reset();
    }

    // Returns the number of packets sent and a FSM context structure.
    fn declare_fault(
        &self,
        user: &mut impl CfdpUser,
        cond: ConditionCode,
    ) -> Result<(u32, FsmContext), SourceError> {
        let mut sent_packets = 0;
        let mut fh = self.local_cfg.fault_handler.get_fault_handler(cond);
        // CFDP standard 4.11.2.2.3: Any fault declared in the course of transferring
        // the EOF (cancel) PDU must result in abandonment of the transaction.
        if let Some(positive_ack_params) = self.transaction_params.positive_ack_params.get() {
            if positive_ack_params.positive_ack_of_cancellation {
                fh = FaultHandlerCode::AbandonTransaction;
            }
        }
        let mut ctx = FsmContext::default();
        match fh {
            FaultHandlerCode::NoticeOfCancellation => {
                ctx = self.notice_of_cancellation_internal(user, cond, &mut sent_packets)?;
            }
            FaultHandlerCode::NoticeOfSuspension => {
                self.notice_of_suspension_internal();
            }
            FaultHandlerCode::IgnoreError => (),
            FaultHandlerCode::AbandonTransaction => {
                ctx = FsmContext::ResetWhenPossible;
            }
        }
        self.local_cfg.fault_handler.report_fault(
            fh,
            FaultInfo::new(
                self.transaction_id().unwrap(),
                cond,
                self.transaction_params.file_params.progress,
            ),
        );
        Ok((sent_packets, ctx))
    }

    fn handle_keep_alive_pdu(&mut self) {}
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write, path::PathBuf, vec::Vec};

    use alloc::string::String;
    use rand::Rng;
    use spacepackets::{
        cfdp::{
            ChecksumType, CrcFlag,
            pdu::{
                file_data::FileDataPdu, finished::FinishedPduCreator, metadata::MetadataPduReader,
                nak::NakPduCreator,
            },
        },
        util::UnsignedByteFieldU16,
    };
    use tempfile::TempPath;

    use super::*;
    use crate::{
        CRC_32, FaultHandler, IndicationConfig, PduRawWithInfo, RemoteConfigStoreStd,
        filestore::NativeFilestore,
        request::PutRequestOwned,
        source::TransactionStep,
        tests::{
            SentPdu, TestCfdpSender, TestCfdpUser, TestCheckTimer, TestCheckTimerCreator,
            TestFaultHandler, TimerExpiryControl, basic_remote_cfg_table,
        },
    };
    use spacepackets::seq_count::SequenceCounterSimple;

    const LOCAL_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(1);
    const REMOTE_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(2);
    const INVALID_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(5);

    fn init_full_filepaths_textfile() -> (TempPath, PathBuf) {
        (
            tempfile::NamedTempFile::new().unwrap().into_temp_path(),
            tempfile::TempPath::from_path("/tmp/test.txt").to_path_buf(),
        )
    }

    type TestSourceHandler = SourceHandler<
        TestCfdpSender,
        TestFaultHandler,
        NativeFilestore,
        RemoteConfigStoreStd,
        TestCheckTimerCreator,
        TestCheckTimer,
        SequenceCounterSimple<u16>,
    >;

    struct SourceHandlerTestbench {
        handler: TestSourceHandler,
        expiry_control: TimerExpiryControl,
        transmission_mode: TransmissionMode,
        #[allow(dead_code)]
        srcfile_handle: TempPath,
        srcfile: String,
        destfile: String,
        max_packet_len: usize,
        check_idle_on_drop: bool,
    }

    #[allow(dead_code)]
    struct TransferInfo {
        id: TransactionId,
        file_size: u64,
        closure_requested: bool,
        pdu_header: PduHeader,
    }

    #[derive(Debug, Clone, Copy)]
    struct EofParams {
        file_size: u64,
        file_checksum: u32,
        condition_code: ConditionCode,
    }

    impl EofParams {
        pub const fn new_success(file_size: u64, file_checksum: u32) -> Self {
            Self {
                file_size,
                file_checksum,
                condition_code: ConditionCode::NoError,
            }
        }
    }

    impl SourceHandlerTestbench {
        fn new(
            transmission_mode: TransmissionMode,
            crc_on_transmission_by_default: bool,
            max_packet_len: usize,
        ) -> Self {
            let local_entity_cfg = LocalEntityConfig {
                id: LOCAL_ID.into(),
                indication_cfg: IndicationConfig::default(),
                fault_handler: FaultHandler::new(TestFaultHandler::default()),
            };
            let static_put_request_cacher = StaticPutRequestCacher::new(2048);
            let (srcfile_handle, destfile) = init_full_filepaths_textfile();
            let srcfile = String::from(srcfile_handle.to_path_buf().to_str().unwrap());
            let expiry_control = TimerExpiryControl::default();
            let sender = TestCfdpSender::default();
            Self {
                handler: SourceHandler::new(
                    local_entity_cfg,
                    sender,
                    NativeFilestore::default(),
                    static_put_request_cacher,
                    1024,
                    basic_remote_cfg_table(
                        REMOTE_ID,
                        max_packet_len,
                        crc_on_transmission_by_default,
                    ),
                    TestCheckTimerCreator::new(&expiry_control),
                    SequenceCounterSimple::default(),
                ),
                transmission_mode,
                expiry_control,
                srcfile_handle,
                srcfile,
                destfile: String::from(destfile.to_path_buf().to_str().unwrap()),
                max_packet_len,
                check_idle_on_drop: true,
            }
        }

        fn create_user(&self, next_expected_seq_num: u64, filesize: u64) -> TestCfdpUser {
            TestCfdpUser::new(
                next_expected_seq_num,
                self.srcfile.clone(),
                self.destfile.clone(),
                filesize,
            )
        }

        fn put_request(
            &mut self,
            put_request: &impl ReadablePutRequest,
        ) -> Result<(), PutRequestError> {
            self.handler.put_request(put_request)
        }

        fn all_fault_queues_empty(&self) -> bool {
            self.handler
                .local_cfg
                .user_fault_hook()
                .borrow()
                .all_queues_empty()
        }

        #[allow(dead_code)]
        fn test_fault_handler(&self) -> &RefCell<TestFaultHandler> {
            self.handler.local_cfg.user_fault_hook()
        }

        fn test_fault_handler_mut(&mut self) -> &mut RefCell<TestFaultHandler> {
            self.handler.local_cfg.user_fault_hook_mut()
        }

        fn pdu_queue_empty(&self) -> bool {
            self.handler.pdu_sender.queue_empty()
        }

        fn get_next_sent_pdu(&self) -> Option<SentPdu> {
            self.handler.pdu_sender.retrieve_next_pdu()
        }

        fn common_pdu_check_for_file_transfer(&self, pdu_header: &PduHeader, crc_flag: CrcFlag) {
            assert_eq!(
                pdu_header.seg_ctrl(),
                SegmentationControl::NoRecordBoundaryPreservation
            );
            assert_eq!(
                pdu_header.seg_metadata_flag(),
                SegmentMetadataFlag::NotPresent
            );
            assert_eq!(pdu_header.common_pdu_conf().source_id(), LOCAL_ID.into());
            assert_eq!(pdu_header.common_pdu_conf().dest_id(), REMOTE_ID.into());
            assert_eq!(pdu_header.common_pdu_conf().crc_flag, crc_flag);
            assert_eq!(
                pdu_header.common_pdu_conf().trans_mode,
                self.transmission_mode
            );
            assert_eq!(
                pdu_header.common_pdu_conf().direction,
                Direction::TowardsReceiver
            );
            assert_eq!(
                pdu_header.common_pdu_conf().file_flag,
                LargeFileFlag::Normal
            );
            assert_eq!(pdu_header.common_pdu_conf().transaction_seq_num.size(), 2);
        }

        fn nak_for_file_segments(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            transfer_info: &TransferInfo,
            seg_reqs: &[(u32, u32)],
        ) {
            let nak_pdu = NakPduCreator::new_normal_file_size(
                transfer_info.pdu_header,
                0,
                transfer_info.file_size as u32,
                seg_reqs,
            )
            .unwrap();
            let nak_pdu_vec = nak_pdu.to_vec().unwrap();
            let packet_info = PduRawWithInfo::new(&nak_pdu_vec).unwrap();
            self.handler
                .state_machine(cfdp_user, Some(&packet_info))
                .unwrap();
        }

        fn generic_file_transfer(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            with_closure: bool,
            file_data: Vec<u8>,
        ) -> (TransferInfo, u32) {
            let mut digest = CRC_32.digest();
            digest.update(&file_data);
            let checksum = digest.finalize();
            cfdp_user.expected_full_src_name = self.srcfile.clone();
            cfdp_user.expected_full_dest_name = self.destfile.clone();
            cfdp_user.expected_file_size = file_data.len() as u64;
            let put_request = PutRequestOwned::new_regular_request(
                REMOTE_ID.into(),
                &self.srcfile,
                &self.destfile,
                Some(self.transmission_mode),
                Some(with_closure),
            )
            .expect("creating put request failed");
            let transaction_info = self.common_file_transfer_init_with_metadata_check(
                cfdp_user,
                put_request,
                cfdp_user.expected_file_size,
            );
            let mut current_offset = 0;
            let chunks = file_data.chunks(
                calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(
                    &transaction_info.pdu_header,
                    self.max_packet_len,
                    None,
                ),
            );
            let mut fd_pdus = 0;
            for segment in chunks {
                self.check_next_file_pdu(current_offset, segment);
                self.handler.state_machine_no_packet(cfdp_user).unwrap();
                fd_pdus += 1;
                current_offset += segment.len() as u64;
            }
            self.common_eof_pdu_check(
                cfdp_user,
                transaction_info.closure_requested,
                EofParams {
                    file_size: cfdp_user.expected_file_size,
                    file_checksum: checksum,
                    condition_code: ConditionCode::NoError,
                },
                1,
            );
            (transaction_info, fd_pdus)
        }

        fn common_file_transfer_init_with_metadata_check(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            put_request: PutRequestOwned,
            file_size: u64,
        ) -> TransferInfo {
            assert_eq!(cfdp_user.transaction_indication_call_count, 0);
            assert_eq!(cfdp_user.eof_sent_call_count, 0);

            self.put_request(&put_request)
                .expect("put_request call failed");
            assert_eq!(self.handler.state(), State::Busy);
            assert_eq!(self.handler.step(), TransactionStep::Idle);
            let transaction_id = self.handler.transaction_id().unwrap();
            let sent_packets = self
                .handler
                .state_machine_no_packet(cfdp_user)
                .expect("source handler FSM failure");
            assert_eq!(sent_packets, 2);
            assert!(!self.pdu_queue_empty());
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert!(!self.pdu_queue_empty());
            let metadata_pdu_reader = self.metadata_check(&next_pdu, file_size);
            let closure_requested = if let Some(closure_requested) = put_request.closure_requested {
                assert_eq!(
                    metadata_pdu_reader.metadata_params().closure_requested,
                    closure_requested
                );
                closure_requested
            } else {
                assert!(metadata_pdu_reader.metadata_params().closure_requested);
                metadata_pdu_reader.metadata_params().closure_requested
            };
            TransferInfo {
                pdu_header: *metadata_pdu_reader.pdu_header(),
                closure_requested,
                file_size,
                id: transaction_id,
            }
        }

        fn metadata_check<'a>(
            &self,
            next_pdu: &'a SentPdu,
            file_size: u64,
        ) -> MetadataPduReader<'a> {
            assert_eq!(next_pdu.pdu_type, PduType::FileDirective);
            assert_eq!(
                next_pdu.file_directive_type,
                Some(FileDirectiveType::MetadataPdu)
            );
            let metadata_pdu =
                MetadataPduReader::new(&next_pdu.raw_pdu).expect("invalid metadata PDU format");
            self.common_pdu_check_for_file_transfer(metadata_pdu.pdu_header(), CrcFlag::NoCrc);
            assert_eq!(
                metadata_pdu
                    .src_file_name()
                    .value_as_str()
                    .unwrap()
                    .unwrap(),
                self.srcfile
            );
            assert_eq!(
                metadata_pdu
                    .dest_file_name()
                    .value_as_str()
                    .unwrap()
                    .unwrap(),
                self.destfile
            );
            assert_eq!(metadata_pdu.metadata_params().file_size, file_size);
            assert_eq!(
                metadata_pdu.metadata_params().checksum_type,
                ChecksumType::Crc32
            );
            assert_eq!(metadata_pdu.transmission_mode(), self.transmission_mode);
            assert_eq!(metadata_pdu.options(), &[]);
            metadata_pdu
        }

        fn check_next_file_pdu(&mut self, expected_offset: u64, expected_data: &[u8]) {
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert_eq!(next_pdu.pdu_type, PduType::FileData);
            assert!(next_pdu.file_directive_type.is_none());
            let fd_pdu =
                FileDataPdu::from_bytes(&next_pdu.raw_pdu).expect("reading file data PDU failed");
            assert_eq!(fd_pdu.offset(), expected_offset);
            assert_eq!(fd_pdu.file_data(), expected_data);
            assert!(fd_pdu.segment_metadata().is_none());
        }

        fn acknowledge_eof_pdu(
            &mut self,
            cfdp_user: &mut impl CfdpUser,
            transaction_info: &TransferInfo,
        ) {
            let ack_pdu = AckPdu::new(
                transaction_info.pdu_header,
                FileDirectiveType::EofPdu,
                ConditionCode::NoError,
                TransactionStatus::Active,
            )
            .expect("creating ACK PDU failed");
            let ack_pdu_vec = ack_pdu.to_vec().unwrap();
            let packet_info = PduRawWithInfo::new(&ack_pdu_vec).unwrap();
            self.handler
                .state_machine(cfdp_user, Some(&packet_info))
                .expect("state machine failed");
        }

        fn common_finished_pdu_ack_check(&mut self) {
            assert!(!self.pdu_queue_empty());
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert!(self.pdu_queue_empty());
            assert_eq!(next_pdu.pdu_type, PduType::FileDirective);
            assert_eq!(
                next_pdu.file_directive_type,
                Some(FileDirectiveType::AckPdu)
            );
            let ack_pdu = AckPdu::from_bytes(&next_pdu.raw_pdu).unwrap();
            self.common_pdu_check_for_file_transfer(ack_pdu.pdu_header(), CrcFlag::NoCrc);
            assert_eq!(ack_pdu.condition_code(), ConditionCode::NoError);
            assert_eq!(
                ack_pdu.directive_code_of_acked_pdu(),
                FileDirectiveType::FinishedPdu
            );
            assert_eq!(ack_pdu.transaction_status(), TransactionStatus::Active);
        }

        fn common_eof_pdu_check(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            closure_requested: bool,
            eof_params: EofParams,
            eof_sent_call_count: u32,
        ) {
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert_eq!(next_pdu.pdu_type, PduType::FileDirective);
            assert_eq!(
                next_pdu.file_directive_type,
                Some(FileDirectiveType::EofPdu)
            );
            let eof_pdu = EofPdu::from_bytes(&next_pdu.raw_pdu).expect("invalid EOF PDU format");
            self.common_pdu_check_for_file_transfer(eof_pdu.pdu_header(), CrcFlag::NoCrc);
            assert_eq!(eof_pdu.condition_code(), eof_params.condition_code);
            assert_eq!(eof_pdu.file_size(), eof_params.file_size);
            assert_eq!(eof_pdu.file_checksum(), eof_params.file_checksum);
            assert_eq!(
                eof_pdu
                    .pdu_header()
                    .common_pdu_conf()
                    .transaction_seq_num
                    .value_const(),
                0
            );
            if self.transmission_mode == TransmissionMode::Unacknowledged {
                if !closure_requested {
                    assert_eq!(self.handler.state(), State::Idle);
                    assert_eq!(self.handler.step(), TransactionStep::Idle);
                } else {
                    assert_eq!(self.handler.state(), State::Busy);
                    assert_eq!(self.handler.step(), TransactionStep::WaitingForFinished);
                }
            } else {
                assert_eq!(self.handler.state(), State::Busy);
                assert_eq!(self.handler.step(), TransactionStep::WaitingForEofAck);
            }

            assert_eq!(cfdp_user.transaction_indication_call_count, 1);
            assert_eq!(cfdp_user.eof_sent_call_count, eof_sent_call_count);
            self.all_fault_queues_empty();
        }

        fn common_tiny_file_transfer(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            with_closure: bool,
        ) -> (&'static str, TransferInfo) {
            let mut file = OpenOptions::new()
                .write(true)
                .open(&self.srcfile)
                .expect("opening file failed");
            let content_str = "Hello World!";
            file.write_all(content_str.as_bytes())
                .expect("writing file content failed");
            drop(file);
            let (transfer_info, fd_pdus) = self.generic_file_transfer(
                cfdp_user,
                with_closure,
                content_str.as_bytes().to_vec(),
            );
            assert_eq!(fd_pdus, 1);
            (content_str, transfer_info)
        }

        // Finish handling: Simulate completion from the destination side by insert finished PDU.
        fn finish_handling(&mut self, user: &mut TestCfdpUser, transfer_info: &TransferInfo) {
            let finished_pdu = FinishedPduCreator::new_no_error(
                transfer_info.pdu_header,
                DeliveryCode::Complete,
                FileStatus::Retained,
            );
            let finished_pdu_vec = finished_pdu.to_vec().unwrap();
            let packet_info = PduRawWithInfo::new(&finished_pdu_vec).unwrap();
            self.handler
                .state_machine(user, Some(&packet_info))
                .unwrap();
        }
    }

    impl Drop for SourceHandlerTestbench {
        fn drop(&mut self) {
            self.all_fault_queues_empty();
            if self.check_idle_on_drop {
                assert_eq!(self.handler.state(), State::Idle);
                assert_eq!(self.handler.step(), TransactionStep::Idle);
            }
        }
    }

    #[test]
    fn test_basic() {
        let tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        assert!(tb.handler.transmission_mode().is_none());
        assert!(tb.pdu_queue_empty());
    }

    #[test]
    fn test_empty_file_transfer_not_acked_no_closure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        let file_size = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transfer_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(
            &mut user,
            transfer_info.closure_requested,
            EofParams::new_success(file_size, CRC_32.digest().finalize()),
            1,
        );
        user.verify_finished_indication(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transfer_info.id,
            FileStatus::Unreported,
        );
    }

    #[test]
    fn test_empty_file_transfer_acked() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let file_size = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Acknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transaction_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(
            &mut user,
            transaction_info.closure_requested,
            EofParams::new_success(file_size, CRC_32.digest().finalize()),
            1,
        );

        tb.acknowledge_eof_pdu(&mut user, &transaction_info);
        tb.finish_handling(&mut user, &transaction_info);
        tb.common_finished_pdu_ack_check();
        user.verify_finished_indication_retained(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transaction_info.id,
        );
    }

    #[test]
    fn test_tiny_file_transfer_not_acked_no_closure() {
        let mut user = TestCfdpUser::default();
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        tb.common_tiny_file_transfer(&mut user, false);
    }

    #[test]
    fn test_tiny_file_transfer_acked() {
        let mut user = TestCfdpUser::default();
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let (_data, transfer_info) = tb.common_tiny_file_transfer(&mut user, false);
        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
    }

    #[test]
    fn test_tiny_file_transfer_not_acked_with_closure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        let mut user = TestCfdpUser::default();
        let (_data, transfer_info) = tb.common_tiny_file_transfer(&mut user, true);
        tb.finish_handling(&mut user, &transfer_info)
    }

    #[test]
    fn test_two_segment_file_transfer_not_acked_no_closure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 128);
        let mut user = TestCfdpUser::default();
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (_, fd_pdus) = tb.generic_file_transfer(&mut user, false, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
    }

    #[test]
    fn test_two_segment_file_transfer_not_acked_with_closure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 128);
        let mut user = TestCfdpUser::default();
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (transfer_info, fd_pdus) =
            tb.generic_file_transfer(&mut user, true, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
        tb.finish_handling(&mut user, &transfer_info)
    }

    #[test]
    fn test_two_segment_file_transfer_acked() {
        let mut user = TestCfdpUser::default();
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 128);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (transfer_info, fd_pdus) =
            tb.generic_file_transfer(&mut user, true, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
    }

    #[test]
    fn test_empty_file_transfer_not_acked_with_closure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        let file_size = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transaction_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(
            &mut user,
            transaction_info.closure_requested,
            EofParams::new_success(file_size, CRC_32.digest().finalize()),
            1,
        );
        tb.finish_handling(&mut user, &transaction_info);
        user.verify_finished_indication_retained(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transaction_info.id,
        );
    }

    #[test]
    fn test_put_request_no_remote_cfg() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);

        let (srcfile, destfile) = init_full_filepaths_textfile();
        let srcfile_str = String::from(srcfile.to_str().unwrap());
        let destfile_str = String::from(destfile.to_str().unwrap());
        let put_request = PutRequestOwned::new_regular_request(
            INVALID_ID.into(),
            &srcfile_str,
            &destfile_str,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let error = tb.handler.put_request(&put_request);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let PutRequestError::NoRemoteCfgFound(id) = error {
            assert_eq!(id, INVALID_ID.into());
        } else {
            panic!("unexpected error type: {:?}", error);
        }
    }

    #[test]
    fn test_put_request_file_does_not_exist() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);

        let file_which_does_not_exist = "/tmp/this_file_does_not_exist.txt";
        let destfile = "/tmp/tmp.txt";
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            file_which_does_not_exist,
            destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let error = tb.put_request(&put_request);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if !matches!(error, PutRequestError::FileDoesNotExist) {
            panic!("unexpected error type: {:?}", error);
        }
    }

    #[test]
    fn test_finished_pdu_check_timeout() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        let file_size = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transaction_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        let expected_id = tb.handler.transaction_id().unwrap();
        tb.common_eof_pdu_check(
            &mut user,
            transaction_info.closure_requested,
            EofParams::new_success(file_size, CRC_32.digest().finalize()),
            1,
        );
        assert!(tb.pdu_queue_empty());

        // Enforce a check limit error by expiring the check limit timer -> leads to a notice of
        // cancellation -> leads to an EOF PDU with the appropriate error code.
        tb.expiry_control.set_check_limit_expired();

        assert_eq!(tb.handler.state_machine_no_packet(&mut user).unwrap(), 1);
        assert!(!tb.pdu_queue_empty());
        let next_pdu = tb.get_next_sent_pdu().unwrap();
        let eof_pdu = EofPdu::from_bytes(&next_pdu.raw_pdu).expect("invalid EOF PDU format");
        tb.common_pdu_check_for_file_transfer(eof_pdu.pdu_header(), CrcFlag::NoCrc);
        assert_eq!(eof_pdu.condition_code(), ConditionCode::CheckLimitReached);
        assert_eq!(eof_pdu.file_size(), 0);
        assert_eq!(eof_pdu.file_checksum(), 0);

        // Cancellation fault should have been triggered.
        let fault_handler = tb.test_fault_handler_mut();
        let fh_ref_mut = fault_handler.get_mut();
        assert!(!fh_ref_mut.cancellation_queue_empty());
        assert_eq!(fh_ref_mut.notice_of_cancellation_queue.len(), 1);
        let FaultInfo {
            transaction_id,
            condition_code,
            progress,
        } = fh_ref_mut.notice_of_cancellation_queue.pop_back().unwrap();
        assert_eq!(transaction_id, expected_id);
        assert_eq!(condition_code, ConditionCode::CheckLimitReached);
        assert_eq!(progress, 0);
        fh_ref_mut.all_queues_empty();
    }

    #[test]
    fn test_cancelled_transfer_empty_file() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 512);
        let filesize = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, filesize);
        assert_eq!(user.transaction_indication_call_count, 0);
        assert_eq!(user.eof_sent_call_count, 0);

        tb.put_request(&put_request)
            .expect("put_request call failed");
        assert_eq!(tb.handler.state(), State::Busy);
        assert_eq!(tb.handler.step(), TransactionStep::Idle);
        assert!(tb.get_next_sent_pdu().is_none());
        let id = tb.handler.transaction_id().unwrap();
        tb.handler
            .cancel_request(&mut user, &id)
            .expect("transaction cancellation failed");
        assert_eq!(tb.handler.state(), State::Idle);
        assert_eq!(tb.handler.step(), TransactionStep::Idle);
        // EOF (Cancel) PDU will be generated
        let eof_pdu = tb
            .get_next_sent_pdu()
            .expect("no EOF PDU generated like expected");
        assert_eq!(
            eof_pdu.file_directive_type.unwrap(),
            FileDirectiveType::EofPdu
        );
        let eof_pdu = EofPdu::from_bytes(&eof_pdu.raw_pdu).unwrap();
        assert_eq!(
            eof_pdu.condition_code(),
            ConditionCode::CancelRequestReceived
        );
        assert_eq!(eof_pdu.file_checksum(), 0);
        assert_eq!(eof_pdu.file_size(), 0);
        tb.common_pdu_check_for_file_transfer(eof_pdu.pdu_header(), CrcFlag::NoCrc);
    }

    #[test]
    fn test_cancelled_transfer_mid_transfer() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Unacknowledged, false, 128);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let file_size = rand_data.len() as u64;
        let mut user = tb.create_user(0, file_size);
        let transaction_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        let mut chunks = rand_data.chunks(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(
                &transaction_info.pdu_header,
                tb.max_packet_len,
                None,
            ),
        );
        let mut digest = CRC_32.digest();
        let first_chunk = chunks.next().expect("no chunk found");
        digest.update(first_chunk);
        let checksum = digest.finalize();
        let next_packet = tb.get_next_sent_pdu().unwrap();
        assert_eq!(next_packet.pdu_type, PduType::FileData);
        let fd_pdu = FileDataPdu::from_bytes(&next_packet.raw_pdu).unwrap();
        assert_eq!(fd_pdu.file_data(), &rand_data[0..first_chunk.len()]);
        let expected_id = tb.handler.transaction_id().unwrap();
        assert!(
            tb.handler
                .cancel_request(&mut user, &expected_id)
                .expect("cancellation failed")
        );
        assert_eq!(tb.handler.state(), State::Idle);
        assert_eq!(tb.handler.step(), TransactionStep::Idle);
        let next_packet = tb.get_next_sent_pdu().unwrap();
        assert_eq!(next_packet.pdu_type, PduType::FileDirective);
        assert_eq!(
            next_packet.file_directive_type.unwrap(),
            FileDirectiveType::EofPdu
        );
        // As specified in 4.11.2.2 of the standard, the file size will be the progress of the
        // file copy operation so far, and the checksum is calculated for that progress.
        let eof_pdu = EofPdu::from_bytes(&next_packet.raw_pdu).expect("EOF PDU creation failed");
        assert_eq!(eof_pdu.file_size(), first_chunk.len() as u64);
        assert_eq!(eof_pdu.file_checksum(), checksum);
        assert_eq!(
            eof_pdu.condition_code(),
            ConditionCode::CancelRequestReceived
        );
    }

    #[test]
    fn test_positive_ack_procedure() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let file_size = 0;
        let eof_params = EofParams {
            file_size,
            file_checksum: CRC_32.digest().finalize(),
            condition_code: ConditionCode::NoError,
        };
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Acknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transfer_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 1);

        assert!(tb.pdu_queue_empty());

        // Enforce a postive ack timer expiry -> leads to a re-send of the EOF PDU.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 2);

        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
        user.verify_finished_indication_retained(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transfer_info.id,
        );
    }

    #[test]
    fn test_positive_ack_procedure_ack_limit_reached() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let file_size = 0;
        let mut eof_params = EofParams::new_success(file_size, CRC_32.digest().finalize());
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Acknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transfer_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 1);

        assert!(tb.pdu_queue_empty());

        // Enforce a postive ack timer expiry -> leads to a re-send of the EOF PDU.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 2);
        // Enforce a postive ack timer expiry -> leads to a re-send of the EOF PDU.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        eof_params.condition_code = ConditionCode::PositiveAckLimitReached;
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 3);
        // This boilerplate handling is still expected. In a real-life use-case I would expect
        // this to fail as well, leading to a transaction abandonment. This is tested separately.
        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
        user.verify_finished_indication_retained(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transfer_info.id,
        );
    }

    #[test]
    fn test_positive_ack_procedure_ack_limit_reached_abandonment() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let file_size = 0;
        let mut eof_params = EofParams::new_success(file_size, CRC_32.digest().finalize());
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Acknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transfer_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 1);

        assert!(tb.pdu_queue_empty());

        // Enforce a postive ack timer expiry -> leads to a re-send of the EOF PDU.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 2);
        // Enforce a postive ack timer expiry -> positive ACK limit reached -> Cancel EOF sent.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        eof_params.condition_code = ConditionCode::PositiveAckLimitReached;
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 3);
        // Cancellation fault should have been triggered.
        let fault_handler = tb.test_fault_handler_mut();
        let fh_ref_mut = fault_handler.get_mut();
        assert!(!fh_ref_mut.cancellation_queue_empty());
        assert_eq!(fh_ref_mut.notice_of_cancellation_queue.len(), 1);
        let FaultInfo {
            transaction_id,
            condition_code,
            progress,
        } = fh_ref_mut.notice_of_cancellation_queue.pop_back().unwrap();
        assert_eq!(transaction_id, transfer_info.id);
        assert_eq!(condition_code, ConditionCode::PositiveAckLimitReached);
        assert_eq!(progress, file_size);
        fh_ref_mut.all_queues_empty();

        // Enforce a postive ack timer expiry -> leads to a re-send of the EOF Cancel PDU.
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 1);
        tb.common_eof_pdu_check(&mut user, transfer_info.closure_requested, eof_params, 4);

        // Enforce a postive ack timer expiry -> positive ACK limit reached -> Transaction
        // abandoned
        tb.expiry_control.set_positive_ack_expired();
        let sent_packets = tb
            .handler
            .state_machine_no_packet(&mut user)
            .expect("source handler FSM failure");
        assert_eq!(sent_packets, 0);
        // Abandonment fault should have been triggered.
        let fault_handler = tb.test_fault_handler_mut();
        let fh_ref_mut = fault_handler.get_mut();
        assert!(!fh_ref_mut.abandoned_queue_empty());
        assert_eq!(fh_ref_mut.abandoned_queue.len(), 1);
        let FaultInfo {
            transaction_id,
            condition_code,
            progress,
        } = fh_ref_mut.abandoned_queue.pop_back().unwrap();
        assert_eq!(transaction_id, transfer_info.id);
        assert_eq!(condition_code, ConditionCode::PositiveAckLimitReached);
        assert_eq!(progress, file_size);
        fh_ref_mut.all_queues_empty();
    }

    #[test]
    fn test_nak_for_whole_file() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let mut user = TestCfdpUser::default();
        let (data, transfer_info) = tb.common_tiny_file_transfer(&mut user, true);
        let seg_reqs = &[(0, transfer_info.file_size as u32)];
        tb.nak_for_file_segments(&mut user, &transfer_info, seg_reqs);
        tb.check_next_file_pdu(0, data.as_bytes());
        tb.all_fault_queues_empty();

        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
    }

    #[test]
    fn test_nak_for_file_segment() {
        let mut user = TestCfdpUser::default();
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 128);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (transfer_info, fd_pdus) =
            tb.generic_file_transfer(&mut user, false, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
        tb.nak_for_file_segments(&mut user, &transfer_info, &[(0, 90)]);
        tb.check_next_file_pdu(0, &rand_data[0..90]);
        tb.all_fault_queues_empty();

        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
    }

    #[test]
    fn test_nak_for_metadata() {
        let mut tb = SourceHandlerTestbench::new(TransmissionMode::Acknowledged, false, 512);
        let file_size = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Acknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut user = tb.create_user(0, file_size);
        let transfer_info =
            tb.common_file_transfer_init_with_metadata_check(&mut user, put_request, file_size);
        tb.common_eof_pdu_check(
            &mut user,
            transfer_info.closure_requested,
            EofParams::new_success(file_size, CRC_32.digest().finalize()),
            1,
        );

        // NAK to cause re-transmission of metadata PDU.
        let nak_pdu = NakPduCreator::new_normal_file_size(
            transfer_info.pdu_header,
            0,
            transfer_info.file_size as u32,
            &[(0, 0)],
        )
        .unwrap();
        let nak_pdu_vec = nak_pdu.to_vec().unwrap();
        let packet_info = PduRawWithInfo::new(&nak_pdu_vec).unwrap();
        let sent_packets = tb
            .handler
            .state_machine(&mut user, Some(&packet_info))
            .unwrap();
        assert_eq!(sent_packets, 1);
        let next_pdu = tb.get_next_sent_pdu().unwrap();
        // Check the metadata PDU.
        tb.metadata_check(&next_pdu, file_size);
        tb.all_fault_queues_empty();

        tb.acknowledge_eof_pdu(&mut user, &transfer_info);
        tb.finish_handling(&mut user, &transfer_info);
        tb.common_finished_pdu_ack_check();
        user.verify_finished_indication_retained(
            DeliveryCode::Complete,
            ConditionCode::NoError,
            transfer_info.id,
        );
    }
}
