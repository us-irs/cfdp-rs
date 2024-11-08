//! # CFDP Source Entity Module
//!
//! The [SourceHandler] is the primary component of this module which converts a
//! [ReadablePutRequest] into all packet data units (PDUs) which need to be sent to a remote
//! CFDP entity to perform a File Copy operation to a remote entity.
//!
//! The source entity allows freedom communication by using a user-provided [PduSendProvider]
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
use core::{cell::RefCell, ops::ControlFlow, str::Utf8Error};

use spacepackets::{
    cfdp::{
        lv::Lv,
        pdu::{
            eof::EofPdu,
            file_data::{
                calculate_max_file_seg_len_for_max_packet_len_and_pdu_header,
                FileDataPduCreatorWithReservedDatafield,
            },
            finished::{DeliveryCode, FileStatus, FinishedPduReader},
            metadata::{MetadataGenericParams, MetadataPduCreator},
            CfdpPdu, CommonPduConfig, FileDirectiveType, PduError, PduHeader, WritablePduPacket,
        },
        ConditionCode, Direction, LargeFileFlag, PduType, SegmentMetadataFlag, SegmentationControl,
        TransmissionMode,
    },
    util::{UnsignedByteField, UnsignedEnum},
    ByteConversionError,
};

use spacepackets::seq_count::SequenceCountProvider;

use crate::{
    time::CountdownProvider, DummyPduProvider, EntityType, GenericSendError, PduProvider,
    TimerCreatorProvider,
};

use super::{
    filestore::{FilestoreError, VirtualFilestore},
    request::{ReadablePutRequest, StaticPutRequestCacher},
    user::{CfdpUser, TransactionFinishedParams},
    LocalEntityConfig, PacketTarget, PduSendProvider, RemoteEntityConfig,
    RemoteEntityConfigProvider, State, TransactionId, UserFaultHookProvider,
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
    // SendingAckOfFinished = 9,
    NoticeOfCompletion = 10,
}

#[derive(Default)]
pub struct FileParams {
    pub progress: u64,
    pub segment_len: u64,
    pub crc32: u32,
    pub metadata_only: bool,
    pub file_size: u64,
    pub empty_file: bool,
}

pub struct StateHelper {
    state: super::State,
    step: TransactionStep,
    num_packets_ready: u32,
}

#[derive(Debug)]
pub struct FinishedParams {
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
}

#[derive(Debug, derive_new::new)]
pub struct TransferState {
    transaction_id: TransactionId,
    remote_cfg: RemoteEntityConfig,
    transmission_mode: super::TransmissionMode,
    closure_requested: bool,
    cond_code_eof: Option<ConditionCode>,
    finished_params: Option<FinishedParams>,
}

impl Default for StateHelper {
    fn default() -> Self {
        Self {
            state: super::State::Idle,
            step: TransactionStep::Idle,
            num_packets_ready: 0,
        }
    }
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

/// This is the primary CFDP source handler. It models the CFDP source entity, which is
/// primarily responsible for handling put requests to send files to another CFDP destination
/// entity.
///
/// As such, it contains a state machine to perform all operations necessary to perform a
/// source-to-destination file transfer. This class uses the user provides [PduSendProvider] to
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
    PduSender: PduSendProvider,
    UserFaultHook: UserFaultHookProvider,
    Vfs: VirtualFilestore,
    RemoteCfgTable: RemoteEntityConfigProvider,
    TimerCreator: TimerCreatorProvider<Countdown = Countdown>,
    Countdown: CountdownProvider,
    SeqCountProvider: SequenceCountProvider,
> {
    local_cfg: LocalEntityConfig<UserFaultHook>,
    pdu_sender: PduSender,
    pdu_and_cksum_buffer: RefCell<alloc::vec::Vec<u8>>,
    put_request_cacher: StaticPutRequestCacher,
    remote_cfg_table: RemoteCfgTable,
    vfs: Vfs,
    state_helper: StateHelper,
    // Transfer related state information
    tstate: Option<TransferState>,
    // File specific transfer fields
    fparams: FileParams,
    // PDU configuration is cached so it can be re-used for all PDUs generated for file transfers.
    pdu_conf: CommonPduConfig,
    countdown: Option<Countdown>,
    timer_creator: TimerCreator,
    seq_count_provider: SeqCountProvider,
}

impl<
        PduSender: PduSendProvider,
        UserFaultHook: UserFaultHookProvider,
        Vfs: VirtualFilestore,
        RemoteCfgTable: RemoteEntityConfigProvider,
        TimerCreator: TimerCreatorProvider<Countdown = Countdown>,
        Countdown: CountdownProvider,
        SeqCountProvider: SequenceCountProvider,
    >
    SourceHandler<
        PduSender,
        UserFaultHook,
        Vfs,
        RemoteCfgTable,
        TimerCreator,
        Countdown,
        SeqCountProvider,
    >
{
    /// Creates a new instance of a source handler.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The local entity configuration for this source handler.
    /// * `pdu_sender` - [PduSendProvider] provider used to send CFDP PDUs generated by the handler.
    /// * `vfs` - [VirtualFilestore] implementation used by the handler, which decouples the CFDP
    ///    implementation from the underlying filestore/filesystem. This allows to use this handler
    ///    for embedded systems where a standard runtime might not be available.
    /// * `put_request_cacher` - The put request cacher is used cache put requests without
    ///    requiring run-time allocation.
    /// * `pdu_and_cksum_buf_size` - The handler requires a buffer to generate PDUs and perform
    ///    checksum calculations. The user can specify the size of this buffer, so this should be
    ///    set to the maximum expected PDU size or a conservative upper bound for this size, for
    ///    example 2048 or 4096 bytes.
    /// * `remote_cfg_table` - The [RemoteEntityConfigProvider] used to look up remote
    ///    entities and target specific configuration for file copy operations.
    /// * `timer_creator` - [TimerCreatorProvider] used by the CFDP handler to generate
    ///    timers required by various tasks. This allows to use this handler for embedded systems
    ///    where the standard time APIs might not be available.
    /// * `seq_count_provider` - The [SequenceCountProvider] used to generate the [TransactionId]
    ///    which contains an incrementing counter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: LocalEntityConfig<UserFaultHook>,
        pdu_sender: PduSender,
        vfs: Vfs,
        put_request_cacher: StaticPutRequestCacher,
        pdu_and_cksum_buf_size: usize,
        remote_cfg_table: RemoteCfgTable,
        timer_creator: TimerCreator,
        seq_count_provider: SeqCountProvider,
    ) -> Self {
        Self {
            local_cfg: cfg,
            remote_cfg_table,
            pdu_sender,
            pdu_and_cksum_buffer: RefCell::new(alloc::vec![0; pdu_and_cksum_buf_size]),
            vfs,
            put_request_cacher,
            state_helper: Default::default(),
            tstate: Default::default(),
            fparams: Default::default(),
            pdu_conf: Default::default(),
            countdown: None,
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
        if let Some(packet) = pdu {
            self.insert_packet(cfdp_user, packet)?;
        }
        match self.state_helper.state {
            super::State::Idle => {
                // TODO: In acknowledged mode, add timer handling.
                Ok(0)
            }
            super::State::Busy => self.fsm_busy(cfdp_user, pdu),
            super::State::Suspended => {
                // There is now way to suspend the handler currently anyway.
                Ok(0)
            }
        }
    }

    fn insert_packet(
        &mut self,
        _cfdp_user: &mut impl CfdpUser,
        packet_to_insert: &impl PduProvider,
    ) -> Result<(), SourceError> {
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
        // Unwrap is okay here, the [PacketInfo] API should ensure that the directive type is
        // always a valid value.
        match packet_to_insert
            .file_directive_type()
            .expect("PDU directive type unexpectedly not set")
        {
            FileDirectiveType::FinishedPdu => self.handle_finished_pdu(packet_to_insert)?,
            FileDirectiveType::NakPdu => self.handle_nak_pdu(),
            FileDirectiveType::KeepAlivePdu => self.handle_keep_alive_pdu(),
            FileDirectiveType::AckPdu => return Err(SourceError::NotImplemented),
            FileDirectiveType::EofPdu
            | FileDirectiveType::PromptPdu
            | FileDirectiveType::MetadataPdu => {
                return Err(SourceError::CantProcessPacketType {
                    pdu_type: packet_to_insert.pdu_type(),
                    directive_type: packet_to_insert.file_directive_type(),
                });
            }
        }
        Ok(())
    }

    /// This function is used to pass a put request to the source handler, which is
    /// also used to start a file copy operation. As such, this function models the Put.request
    /// CFDP primtiive.

    /// Please note that the source handler can also process one put request at a time.
    /// The caller is responsible of creating a new source handler, one handler can only handle
    /// one file copy request at a time.
    pub fn put_request(
        &mut self,
        put_request: &impl ReadablePutRequest,
    ) -> Result<(), PutRequestError> {
        if self.state_helper.state != super::State::Idle {
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
        self.state_helper.num_packets_ready = 0;
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
                SeqCountProvider::MAX_BIT_WIDTH / 8,
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
        self.pdu_conf
            .set_source_and_dest_id(
                create_id(&self.local_cfg.id),
                create_id(&self.put_request_cacher.static_fields.destination_id),
            )
            .unwrap();
        // Set up other PDU configuration fields.
        self.pdu_conf.direction = Direction::TowardsReceiver;
        self.pdu_conf.crc_flag = remote_cfg.crc_on_transmission_by_default.into();
        self.pdu_conf.transaction_seq_num = *transaction_id.seq_num();
        self.pdu_conf.trans_mode = transmission_mode;
        self.fparams.segment_len = self.calculate_max_file_seg_len(remote_cfg);

        // Set up the transfer context structure.
        self.tstate = Some(TransferState {
            transaction_id,
            remote_cfg: *remote_cfg,
            transmission_mode,
            closure_requested,
            cond_code_eof: None,
            finished_params: None,
        });
        self.state_helper.state = super::State::Busy;
        Ok(())
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
        if self.state_helper.state == super::State::Idle {
            return Ok(false);
        }
        if let Some(active_id) = self.transaction_id() {
            if active_id == *transaction_id {
                self.notice_of_cancellation(user, ConditionCode::CancelRequestReceived)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn fsm_busy(
        &mut self,
        user: &mut impl CfdpUser,
        pdu: Option<&impl PduProvider>,
    ) -> Result<u32, SourceError> {
        let mut sent_packets = 0;
        if self.state_helper.step == TransactionStep::Idle {
            self.state_helper.step = TransactionStep::TransactionStart;
        }
        if self.state_helper.step == TransactionStep::TransactionStart {
            self.handle_transaction_start(user)?;
            self.state_helper.step = TransactionStep::SendingMetadata;
        }
        if self.state_helper.step == TransactionStep::SendingMetadata {
            self.prepare_and_send_metadata_pdu()?;
            self.state_helper.step = TransactionStep::SendingFileData;
            sent_packets += 1;
        }
        if self.state_helper.step == TransactionStep::SendingFileData {
            if let ControlFlow::Break(packets) = self.file_data_fsm()? {
                sent_packets += packets;
                // Exit for each file data PDU to allow flow control.
                return Ok(sent_packets);
            }
        }
        if self.state_helper.step == TransactionStep::SendingEof {
            self.eof_fsm(user)?;
            sent_packets += 1;
        }
        if self.state_helper.step == TransactionStep::WaitingForFinished {
            self.handle_wait_for_finished_pdu(user, pdu)?;
        }
        if self.state_helper.step == TransactionStep::NoticeOfCompletion {
            self.notice_of_completion(user);
            self.reset();
        }
        Ok(sent_packets)
    }

    fn handle_wait_for_finished_pdu(
        &mut self,
        user: &mut impl CfdpUser,
        packet: Option<&impl PduProvider>,
    ) -> Result<(), SourceError> {
        if let Some(packet) = packet {
            if let Some(FileDirectiveType::FinishedPdu) = packet.file_directive_type() {
                let finished_pdu = FinishedPduReader::new(packet.pdu())?;
                self.tstate.as_mut().unwrap().finished_params = Some(FinishedParams {
                    condition_code: finished_pdu.condition_code(),
                    delivery_code: finished_pdu.delivery_code(),
                    file_status: finished_pdu.file_status(),
                });
                if self.transmission_mode().unwrap() == TransmissionMode::Acknowledged {
                    // TODO: Ack packet handling
                    self.state_helper.step = TransactionStep::NoticeOfCompletion;
                } else {
                    self.state_helper.step = TransactionStep::NoticeOfCompletion;
                }
                return Ok(());
            }
        }
        // If we reach this state, countdown is definitely valid instance.
        if self.countdown.as_ref().unwrap().has_expired() {
            self.declare_fault(user, ConditionCode::CheckLimitReached)?;
        }
        /*
        def _handle_wait_for_finish(self):
            if (
                self.transmission_mode == TransmissionMode.ACKNOWLEDGED
                and self.__handle_retransmission()
            ):
                return
            if (
                self._inserted_pdu.pdu is None
                or self._inserted_pdu.pdu_directive_type is None
                or self._inserted_pdu.pdu_directive_type != DirectiveType.FINISHED_PDU
            ):
                if self._params.check_timer is not None:
                    if self._params.check_timer.timed_out():
                        self._declare_fault(ConditionCode.CHECK_LIMIT_REACHED)
                return
            finished_pdu = self._inserted_pdu.to_finished_pdu()
            self._inserted_pdu.pdu = None
            self._params.finished_params = finished_pdu.finished_params
            if self.transmission_mode == TransmissionMode.ACKNOWLEDGED:
                self._prepare_finished_ack_packet(finished_pdu.condition_code)
                self.states.step = TransactionStep.SENDING_ACK_OF_FINISHED
            else:
                self.states.step = TransactionStep.NOTICE_OF_COMPLETION
                */
        Ok(())
    }

    fn eof_fsm(&mut self, user: &mut impl CfdpUser) -> Result<(), SourceError> {
        let tstate = self.tstate.as_ref().unwrap();
        let checksum = self.vfs.calculate_checksum(
            self.put_request_cacher.source_file().unwrap(),
            tstate.remote_cfg.default_crc_type,
            self.fparams.file_size,
            self.pdu_and_cksum_buffer.get_mut(),
        )?;
        self.prepare_and_send_eof_pdu(user, checksum)?;
        let tstate = self.tstate.as_ref().unwrap();
        if tstate.transmission_mode == TransmissionMode::Unacknowledged {
            if tstate.closure_requested {
                self.countdown = Some(self.timer_creator.create_countdown(
                    crate::TimerContext::CheckLimit {
                        local_id: self.local_cfg.id,
                        remote_id: tstate.remote_cfg.entity_id,
                        entity_type: EntityType::Sending,
                    },
                ));
                self.state_helper.step = TransactionStep::WaitingForFinished;
            } else {
                self.state_helper.step = TransactionStep::NoticeOfCompletion;
            }
        } else {
            // TODO: Start positive ACK procedure.
        }
        /*
        if self.cfg.indication_cfg.eof_sent_indication_required:
            assert self._params.transaction_id is not None
            self.user.eof_sent_indication(self._params.transaction_id)
        if self.transmission_mode == TransmissionMode.UNACKNOWLEDGED:
            if self._params.closure_requested:
                assert self._params.remote_cfg is not None
                self._params.check_timer = (
                    self.check_timer_provider.provide_check_timer(
                        local_entity_id=self.cfg.local_entity_id,
                        remote_entity_id=self._params.remote_cfg.entity_id,
                        entity_type=EntityType.SENDING,
                    )
                )
                self.states.step = TransactionStep.WAITING_FOR_FINISHED
            else:
                self.states.step = TransactionStep.NOTICE_OF_COMPLETION
        else:
            self._start_positive_ack_procedure()
            */
        Ok(())
    }

    fn handle_transaction_start(
        &mut self,
        cfdp_user: &mut impl CfdpUser,
    ) -> Result<(), SourceError> {
        let tstate = self
            .tstate
            .as_ref()
            .expect("transfer state unexpectedly empty");
        if !self.put_request_cacher.has_source_file() {
            self.fparams.metadata_only = true;
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
            self.fparams.file_size = self.vfs.file_size(source_file)?;
            if self.fparams.file_size > u32::MAX as u64 {
                self.pdu_conf.file_flag = LargeFileFlag::Large
            } else {
                if self.fparams.file_size == 0 {
                    self.fparams.empty_file = true;
                }
                self.pdu_conf.file_flag = LargeFileFlag::Normal
            }
        }
        cfdp_user.transaction_indication(&tstate.transaction_id);
        Ok(())
    }

    fn prepare_and_send_metadata_pdu(&mut self) -> Result<(), SourceError> {
        let tstate = self
            .tstate
            .as_ref()
            .expect("transfer state unexpectedly empty");
        let metadata_params = MetadataGenericParams::new(
            tstate.closure_requested,
            tstate.remote_cfg.default_crc_type,
            self.fparams.file_size,
        );
        if self.fparams.metadata_only {
            let metadata_pdu = MetadataPduCreator::new(
                PduHeader::new_no_file_data(self.pdu_conf, 0),
                metadata_params,
                Lv::new_empty(),
                Lv::new_empty(),
                self.put_request_cacher.opts_slice(),
            );
            return self.pdu_send_helper(&metadata_pdu);
        }
        let metadata_pdu = MetadataPduCreator::new(
            PduHeader::new_no_file_data(self.pdu_conf, 0),
            metadata_params,
            Lv::new_from_str(self.put_request_cacher.source_file().unwrap()).unwrap(),
            Lv::new_from_str(self.put_request_cacher.dest_file().unwrap()).unwrap(),
            self.put_request_cacher.opts_slice(),
        );
        self.pdu_send_helper(&metadata_pdu)
    }

    fn file_data_fsm(&mut self) -> Result<ControlFlow<u32>, SourceError> {
        if self.transmission_mode().unwrap() == super::TransmissionMode::Acknowledged {
            // TODO: Handle re-transmission
        }
        if !self.fparams.metadata_only
            && self.fparams.progress < self.fparams.file_size
            && self.send_progressing_file_data_pdu()?
        {
            return Ok(ControlFlow::Break(1));
        }
        if self.fparams.empty_file || self.fparams.progress >= self.fparams.file_size {
            // EOF is still expected.
            self.state_helper.step = TransactionStep::SendingEof;
            self.tstate.as_mut().unwrap().cond_code_eof = Some(ConditionCode::NoError);
        } else if self.fparams.metadata_only {
            // Special case: Metadata Only, no EOF required.
            if self.tstate.as_ref().unwrap().closure_requested {
                self.state_helper.step = TransactionStep::WaitingForFinished;
            } else {
                self.state_helper.step = TransactionStep::NoticeOfCompletion;
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    fn notice_of_completion(&mut self, cfdp_user: &mut impl CfdpUser) {
        let tstate = self.tstate.as_ref().unwrap();
        if self.local_cfg.indication_cfg.transaction_finished {
            // The first case happens for unacknowledged file copy operation with no closure.
            let finished_params = if tstate.finished_params.is_none() {
                TransactionFinishedParams {
                    id: tstate.transaction_id,
                    condition_code: ConditionCode::NoError,
                    delivery_code: DeliveryCode::Complete,
                    file_status: FileStatus::Unreported,
                }
            } else {
                let finished_params = tstate.finished_params.as_ref().unwrap();
                TransactionFinishedParams {
                    id: tstate.transaction_id,
                    condition_code: finished_params.condition_code,
                    delivery_code: finished_params.delivery_code,
                    file_status: finished_params.file_status,
                }
            };
            cfdp_user.transaction_finished_indication(&finished_params);
        }
    }

    fn calculate_max_file_seg_len(&self, remote_cfg: &RemoteEntityConfig) -> u64 {
        let mut derived_max_seg_len = calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(
            &PduHeader::new_no_file_data(self.pdu_conf, 0),
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
        if self.fparams.progress >= self.fparams.file_size {
            return Ok(false);
        }
        let read_len = if self.fparams.file_size < self.fparams.segment_len {
            self.fparams.file_size
        } else if self.fparams.progress + self.fparams.segment_len > self.fparams.file_size {
            self.fparams.file_size - self.fparams.progress
        } else {
            self.fparams.segment_len
        };
        let pdu_creator = FileDataPduCreatorWithReservedDatafield::new_no_seg_metadata(
            PduHeader::new_for_file_data(
                self.pdu_conf,
                0,
                SegmentMetadataFlag::NotPresent,
                SegmentationControl::NoRecordBoundaryPreservation,
            ),
            self.fparams.progress,
            read_len,
        );
        let mut unwritten_pdu =
            pdu_creator.write_to_bytes_partially(self.pdu_and_cksum_buffer.get_mut())?;
        self.vfs.read_data(
            self.put_request_cacher.source_file().unwrap(),
            self.fparams.progress,
            read_len,
            unwritten_pdu.file_data_field_mut(),
        )?;
        let written_len = unwritten_pdu.finish();
        self.pdu_sender.send_pdu(
            PduType::FileData,
            None,
            &self.pdu_and_cksum_buffer.borrow()[0..written_len],
        )?;
        self.fparams.progress += read_len;
        /*
                """Generic function to prepare a file data PDU. This function can also be used to
                re-transmit file data PDUs of segments which were already sent."""
                assert self._put_req is not None
                assert self._put_req.source_file is not None
                with open(self._put_req.source_file, "rb") as of:
                    file_data = self.user.vfs.read_from_opened_file(of, offset, read_len)
                    # TODO: Support for record continuation state not implemented yet. Segment metadata
                    #       flag is therefore always set to False. Segment metadata support also omitted
                    #       for now. Implementing those generically could be done in form of a callback,
                    #       e.g. abstractmethod of this handler as a first way, another one being
                    #       to expect the user to supply some helper class to split up a file
                    fd_params = FileDataParams(
                        file_data=file_data, offset=offset, segment_metadata=None
                    )
                    file_data_pdu = FileDataPdu(
                        pdu_conf=self._params.pdu_conf, params=fd_params
                    )
                    self._add_packet_to_be_sent(file_data_pdu)
        */
        /*
        """Prepare the next file data PDU, which also progresses the file copy operation.

        :return: True if a packet was prepared, False if PDU handling is done and the next steps
            in the Copy File procedure can be performed
        """
        # This function should only be called if file segments still need to be sent.
        assert self._params.fp.progress < self._params.fp.file_size
        if self._params.fp.file_size < self._params.fp.segment_len:
            read_len = self._params.fp.file_size
        else:
            if (
                self._params.fp.progress + self._params.fp.segment_len
                > self._params.fp.file_size
            ):
                read_len = self._params.fp.file_size - self._params.fp.progress
            else:
                read_len = self._params.fp.segment_len
        self._prepare_file_data_pdu(self._params.fp.progress, read_len)
        self._params.fp.progress += read_len
            */
        Ok(true)
    }

    fn prepare_and_send_eof_pdu(
        &mut self,
        cfdp_user: &mut impl CfdpUser,
        checksum: u32,
    ) -> Result<(), SourceError> {
        let tstate = self
            .tstate
            .as_ref()
            .expect("transfer state unexpectedly empty");
        let eof_pdu = EofPdu::new(
            PduHeader::new_no_file_data(self.pdu_conf, 0),
            tstate.cond_code_eof.unwrap_or(ConditionCode::NoError),
            checksum,
            self.fparams.progress,
            None,
        );
        self.pdu_send_helper(&eof_pdu)?;
        if self.local_cfg.indication_cfg.eof_sent {
            cfdp_user.eof_sent_indication(&tstate.transaction_id);
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

    fn handle_finished_pdu(&mut self, pdu_provider: &impl PduProvider) -> Result<(), SourceError> {
        // Ignore this packet when we are idle.
        if self.state_helper.state == State::Idle {
            return Ok(());
        }
        if self.state_helper.step != TransactionStep::WaitingForFinished {
            return Err(SourceError::UnexpectedPdu {
                pdu_type: PduType::FileDirective,
                directive_type: Some(FileDirectiveType::FinishedPdu),
            });
        }
        let finished_pdu = FinishedPduReader::new(pdu_provider.pdu())?;
        // Unwrapping should be fine here, the transfer state is valid when we are not in IDLE
        // mode.
        self.tstate.as_mut().unwrap().finished_params = Some(FinishedParams {
            condition_code: finished_pdu.condition_code(),
            delivery_code: finished_pdu.delivery_code(),
            file_status: finished_pdu.file_status(),
        });
        if self.tstate.as_ref().unwrap().transmission_mode == TransmissionMode::Acknowledged {
            // TODO: Send ACK packet here immediately and continue.
            //self.state_helper.step = TransactionStep::SendingAckOfFinished;
        }
        self.state_helper.step = TransactionStep::NoticeOfCompletion;

        /*
        if self.transmission_mode == TransmissionMode.ACKNOWLEDGED:
            self._prepare_finished_ack_packet(finished_pdu.condition_code)
            self.states.step = TransactionStep.SENDING_ACK_OF_FINISHED
        else:
            self.states.step = TransactionStep.NOTICE_OF_COMPLETION
        */
        Ok(())
    }

    fn handle_nak_pdu(&mut self) {}

    fn handle_keep_alive_pdu(&mut self) {}

    pub fn transaction_id(&self) -> Option<TransactionId> {
        self.tstate.as_ref().map(|v| v.transaction_id)
    }

    /// Returns the [TransmissionMode] for the active file operation.
    #[inline]
    pub fn transmission_mode(&self) -> Option<super::TransmissionMode> {
        self.tstate.as_ref().map(|v| v.transmission_mode)
    }

    /// Get the [TransactionStep], which denotes the exact step of a pending CFDP transaction when
    /// applicable.
    pub fn step(&self) -> TransactionStep {
        self.state_helper.step
    }

    pub fn state(&self) -> State {
        self.state_helper.state
    }

    pub fn local_cfg(&self) -> &LocalEntityConfig<UserFaultHook> {
        &self.local_cfg
    }

    fn declare_fault(
        &mut self,
        user: &mut impl CfdpUser,
        cond: ConditionCode,
    ) -> Result<(), SourceError> {
        // Need to cache those in advance, because a notice of cancellation can reset the handler.
        let transaction_id = self.tstate.as_ref().unwrap().transaction_id;
        let progress = self.fparams.progress;
        let fh = self.local_cfg.fault_handler.get_fault_handler(cond);
        match fh {
            spacepackets::cfdp::FaultHandlerCode::NoticeOfCancellation => {
                if let ControlFlow::Break(_) = self.notice_of_cancellation(user, cond)? {
                    return Ok(());
                }
            }
            spacepackets::cfdp::FaultHandlerCode::NoticeOfSuspension => {
                self.notice_of_suspension();
            }
            spacepackets::cfdp::FaultHandlerCode::IgnoreError => (),
            spacepackets::cfdp::FaultHandlerCode::AbandonTransaction => self.abandon_transaction(),
        }
        self.local_cfg
            .fault_handler
            .report_fault(transaction_id, cond, progress);
        Ok(())
    }

    fn notice_of_cancellation(
        &mut self,
        user: &mut impl CfdpUser,
        condition_code: ConditionCode,
    ) -> Result<ControlFlow<()>, SourceError> {
        let transaction_id = self.tstate.as_ref().unwrap().transaction_id;
        // CFDP standard 4.11.2.2.3: Any fault declared in the course of transferring
        // the EOF (cancel) PDU must result in abandonment of the transaction.
        if let Some(cond_code_eof) = self.tstate.as_ref().unwrap().cond_code_eof {
            if cond_code_eof != ConditionCode::NoError {
                // Still call the abandonment callback to ensure the fault is logged.
                self.local_cfg
                    .fault_handler
                    .user_hook
                    .get_mut()
                    .abandoned_cb(transaction_id, cond_code_eof, self.fparams.progress);
                self.abandon_transaction();
                return Ok(ControlFlow::Break(()));
            }
        }

        let tstate = self.tstate.as_mut().unwrap();
        tstate.cond_code_eof = Some(condition_code);
        // As specified in 4.11.2.2, prepare an EOF PDU to be sent to the remote entity. Supply
        // the checksum for the file copy progress sent so far.
        let checksum = self.vfs.calculate_checksum(
            self.put_request_cacher.source_file().unwrap(),
            tstate.remote_cfg.default_crc_type,
            self.fparams.progress,
            self.pdu_and_cksum_buffer.get_mut(),
        )?;
        self.prepare_and_send_eof_pdu(user, checksum)?;
        if self.transmission_mode().unwrap() == TransmissionMode::Unacknowledged {
            // We are done.
            self.reset();
        } else {
            self.state_helper.step = TransactionStep::WaitingForEofAck;
        }
        Ok(ControlFlow::Continue(()))
    }

    fn notice_of_suspension(&mut self) {}

    fn abandon_transaction(&mut self) {
        // I guess an abandoned transaction just stops whatever the handler is doing and resets
        // it to a clean state.. The implementation for this is quite easy.
        self.reset();
    }

    /*
    def _notice_of_cancellation(self, condition_code: ConditionCode) -> bool:
        """Returns whether the fault declaration handler can returns prematurely."""
        # CFDP standard 4.11.2.2.3: Any fault declared in the course of transferring
        # the EOF (cancel) PDU must result in abandonment of the transaction.
        if (
            self._params.cond_code_eof is not None
            and self._params.cond_code_eof != ConditionCode.NO_ERROR
        ):
            assert self._params.transaction_id is not None
            # We still call the abandonment callback to ensure the fault is logged.
            self.cfg.default_fault_handlers.abandoned_cb(
                self._params.transaction_id,
                self._params.cond_code_eof,
                self._params.fp.progress,
            )
            self._abandon_transaction()
            return False
        self._params.cond_code_eof = condition_code
        # As specified in 4.11.2.2, prepare an EOF PDU to be sent to the remote entity. Supply
        # the checksum for the file copy progress sent so far.
        self._prepare_eof_pdu(self._checksum_calculation(self._params.fp.progress))
        self.states.step = TransactionStep.SENDING_EOF
        return True
    */

    /// This function is public to allow completely resetting the handler, but it is explicitely
    /// discouraged to do this. CFDP has mechanism to detect issues and errors on itself.
    /// Resetting the handler might interfere with these mechanisms and lead to unexpected
    /// behaviour.
    pub fn reset(&mut self) {
        self.state_helper = Default::default();
        self.tstate = None;
        self.fparams = Default::default();
        self.countdown = None;
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::{fs::OpenOptions, io::Write, path::PathBuf, thread, vec::Vec};

    use alloc::string::String;
    use rand::Rng;
    use spacepackets::{
        cfdp::{
            pdu::{
                file_data::FileDataPdu, finished::FinishedPduCreator, metadata::MetadataPduReader,
            },
            ChecksumType, CrcFlag,
        },
        util::UnsignedByteFieldU16,
    };
    use tempfile::TempPath;

    use super::*;
    use crate::{
        filestore::NativeFilestore,
        request::PutRequestOwned,
        source::TransactionStep,
        tests::{basic_remote_cfg_table, SentPdu, TestCfdpSender, TestCfdpUser, TestFaultHandler},
        FaultHandler, IndicationConfig, PduRawWithInfo, StdCountdown,
        StdRemoteEntityConfigProvider, StdTimerCreator, CRC_32,
    };
    use spacepackets::seq_count::SeqCountProviderSimple;

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
        StdRemoteEntityConfigProvider,
        StdTimerCreator,
        StdCountdown,
        SeqCountProviderSimple<u16>,
    >;

    struct SourceHandlerTestbench {
        handler: TestSourceHandler,
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
        closure_requested: bool,
        pdu_header: PduHeader,
    }

    impl SourceHandlerTestbench {
        fn new(
            crc_on_transmission_by_default: bool,
            test_fault_handler: TestFaultHandler,
            test_packet_sender: TestCfdpSender,
            max_packet_len: usize,
        ) -> Self {
            let local_entity_cfg = LocalEntityConfig {
                id: LOCAL_ID.into(),
                indication_cfg: IndicationConfig::default(),
                fault_handler: FaultHandler::new(test_fault_handler),
            };
            let static_put_request_cacher = StaticPutRequestCacher::new(2048);
            let (srcfile_handle, destfile) = init_full_filepaths_textfile();
            let srcfile = String::from(srcfile_handle.to_path_buf().to_str().unwrap());
            Self {
                handler: SourceHandler::new(
                    local_entity_cfg,
                    test_packet_sender,
                    NativeFilestore::default(),
                    static_put_request_cacher,
                    1024,
                    basic_remote_cfg_table(
                        REMOTE_ID,
                        max_packet_len,
                        crc_on_transmission_by_default,
                    ),
                    StdTimerCreator::new(core::time::Duration::from_millis(100)),
                    SeqCountProviderSimple::default(),
                ),
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

        fn set_check_limit_timeout(&mut self, timeout: Duration) {
            self.handler.timer_creator.check_limit_timeout = timeout;
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
                TransmissionMode::Unacknowledged
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

        fn generic_file_transfer(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            with_closure: bool,
            file_data: Vec<u8>,
        ) -> (PduHeader, u32) {
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
                Some(TransmissionMode::Unacknowledged),
                Some(with_closure),
            )
            .expect("creating put request failed");
            let transaction_info = self.common_no_acked_file_transfer(
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
                cfdp_user.expected_file_size,
                checksum,
            );
            (transaction_info.pdu_header, fd_pdus)
        }

        fn common_no_acked_file_transfer(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            put_request: PutRequestOwned,
            filesize: u64,
        ) -> TransferInfo {
            assert_eq!(cfdp_user.transaction_indication_call_count, 0);
            assert_eq!(cfdp_user.eof_sent_call_count, 0);

            self.put_request(&put_request)
                .expect("put_request call failed");
            assert_eq!(self.handler.state(), State::Busy);
            assert_eq!(self.handler.step(), TransactionStep::Idle);
            let id = self.handler.transaction_id().unwrap();
            let sent_packets = self
                .handler
                .state_machine_no_packet(cfdp_user)
                .expect("source handler FSM failure");
            assert_eq!(sent_packets, 2);
            assert!(!self.pdu_queue_empty());
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert!(!self.pdu_queue_empty());
            assert_eq!(next_pdu.pdu_type, PduType::FileDirective);
            assert_eq!(
                next_pdu.file_directive_type,
                Some(FileDirectiveType::MetadataPdu)
            );
            let metadata_pdu =
                MetadataPduReader::new(&next_pdu.raw_pdu).expect("invalid metadata PDU format");
            let pdu_header = metadata_pdu.pdu_header();
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
            assert_eq!(metadata_pdu.metadata_params().file_size, filesize);
            assert_eq!(
                metadata_pdu.metadata_params().checksum_type,
                ChecksumType::Crc32
            );
            let closure_requested = if let Some(closure_requested) = put_request.closure_requested {
                assert_eq!(
                    metadata_pdu.metadata_params().closure_requested,
                    closure_requested
                );
                closure_requested
            } else {
                assert!(metadata_pdu.metadata_params().closure_requested);
                metadata_pdu.metadata_params().closure_requested
            };
            assert_eq!(metadata_pdu.options(), &[]);
            TransferInfo {
                pdu_header: *pdu_header,
                closure_requested,
                id,
            }
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

        fn common_eof_pdu_check(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            closure_requested: bool,
            filesize: u64,
            checksum: u32,
        ) {
            let next_pdu = self.get_next_sent_pdu().unwrap();
            assert_eq!(next_pdu.pdu_type, PduType::FileDirective);
            assert_eq!(
                next_pdu.file_directive_type,
                Some(FileDirectiveType::EofPdu)
            );
            let eof_pdu = EofPdu::from_bytes(&next_pdu.raw_pdu).expect("invalid EOF PDU format");
            self.common_pdu_check_for_file_transfer(eof_pdu.pdu_header(), CrcFlag::NoCrc);
            assert_eq!(eof_pdu.condition_code(), ConditionCode::NoError);
            assert_eq!(eof_pdu.file_size(), filesize);
            assert_eq!(eof_pdu.file_checksum(), checksum);
            assert_eq!(
                eof_pdu
                    .pdu_header()
                    .common_pdu_conf()
                    .transaction_seq_num
                    .value_const(),
                0
            );
            if !closure_requested {
                assert_eq!(self.handler.state(), State::Idle);
                assert_eq!(self.handler.step(), TransactionStep::Idle);
            } else {
                assert_eq!(self.handler.state(), State::Busy);
                assert_eq!(self.handler.step(), TransactionStep::WaitingForFinished);
            }
            assert_eq!(cfdp_user.transaction_indication_call_count, 1);
            assert_eq!(cfdp_user.eof_sent_call_count, 1);
            self.all_fault_queues_empty();
        }

        fn common_tiny_file_transfer(
            &mut self,
            cfdp_user: &mut TestCfdpUser,
            with_closure: bool,
        ) -> PduHeader {
            let mut file = OpenOptions::new()
                .write(true)
                .open(&self.srcfile)
                .expect("opening file failed");
            let content_str = "Hello World!";
            file.write_all(content_str.as_bytes())
                .expect("writing file content failed");
            drop(file);
            let (pdu_header, fd_pdus) = self.generic_file_transfer(
                cfdp_user,
                with_closure,
                content_str.as_bytes().to_vec(),
            );
            assert_eq!(fd_pdus, 1);
            pdu_header
        }

        fn finish_handling(&mut self, user: &mut TestCfdpUser, pdu_header: PduHeader) {
            let finished_pdu = FinishedPduCreator::new_default(
                pdu_header,
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
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        assert!(tb.handler.transmission_mode().is_none());
        assert!(tb.pdu_queue_empty());
    }

    #[test]
    fn test_empty_file_transfer_not_acked_no_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        let filesize = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut cfdp_user = tb.create_user(0, filesize);
        let transaction_info =
            tb.common_no_acked_file_transfer(&mut cfdp_user, put_request, filesize);
        tb.common_eof_pdu_check(
            &mut cfdp_user,
            transaction_info.closure_requested,
            filesize,
            CRC_32.digest().finalize(),
        )
    }

    #[test]
    fn test_tiny_file_transfer_not_acked_no_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut cfdp_user = TestCfdpUser::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        tb.common_tiny_file_transfer(&mut cfdp_user, false);
    }

    #[test]
    fn test_tiny_file_transfer_not_acked_with_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        let mut cfdp_user = TestCfdpUser::default();
        let pdu_header = tb.common_tiny_file_transfer(&mut cfdp_user, true);
        tb.finish_handling(&mut cfdp_user, pdu_header)
    }

    #[test]
    fn test_two_segment_file_transfer_not_acked_no_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 128);
        let mut cfdp_user = TestCfdpUser::default();
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::thread_rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (_, fd_pdus) = tb.generic_file_transfer(&mut cfdp_user, false, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
    }

    #[test]
    fn test_two_segment_file_transfer_not_acked_with_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 128);
        let mut cfdp_user = TestCfdpUser::default();
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::thread_rng().fill(&mut rand_data[..]);
        file.write_all(&rand_data)
            .expect("writing file content failed");
        drop(file);
        let (pdu_header, fd_pdus) =
            tb.generic_file_transfer(&mut cfdp_user, true, rand_data.to_vec());
        assert_eq!(fd_pdus, 2);
        tb.finish_handling(&mut cfdp_user, pdu_header)
    }

    #[test]
    fn test_empty_file_transfer_not_acked_with_closure() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        let filesize = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let mut cfdp_user = tb.create_user(0, filesize);
        let transaction_info =
            tb.common_no_acked_file_transfer(&mut cfdp_user, put_request, filesize);
        tb.common_eof_pdu_check(
            &mut cfdp_user,
            transaction_info.closure_requested,
            filesize,
            CRC_32.digest().finalize(),
        );
        tb.finish_handling(&mut cfdp_user, transaction_info.pdu_header)
    }

    #[test]
    fn test_put_request_no_remote_cfg() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);

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
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);

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
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        tb.set_check_limit_timeout(Duration::from_millis(45));
        let filesize = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(true),
        )
        .expect("creating put request failed");
        let mut cfdp_user = tb.create_user(0, filesize);
        let transaction_info =
            tb.common_no_acked_file_transfer(&mut cfdp_user, put_request, filesize);
        let expected_id = tb.handler.transaction_id().unwrap();
        tb.common_eof_pdu_check(
            &mut cfdp_user,
            transaction_info.closure_requested,
            filesize,
            CRC_32.digest().finalize(),
        );
        // After 50 ms delay, we run into a timeout, which leads to a check limit error
        // declaration -> leads to a notice of cancellation -> leads to an EOF PDU with the
        // appropriate error code.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            tb.handler.state_machine_no_packet(&mut cfdp_user).unwrap(),
            0
        );
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
        let (id, cond_code, progress) = fh_ref_mut.notice_of_cancellation_queue.pop_back().unwrap();
        assert_eq!(id, expected_id);
        assert_eq!(cond_code, ConditionCode::CheckLimitReached);
        assert_eq!(progress, 0);
        fh_ref_mut.all_queues_empty();
    }

    #[test]
    fn test_cancelled_transfer_empty_file() {
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 512);
        let filesize = 0;
        let put_request = PutRequestOwned::new_regular_request(
            REMOTE_ID.into(),
            &tb.srcfile,
            &tb.destfile,
            Some(TransmissionMode::Unacknowledged),
            Some(false),
        )
        .expect("creating put request failed");
        let mut cfdp_user = tb.create_user(0, filesize);
        assert_eq!(cfdp_user.transaction_indication_call_count, 0);
        assert_eq!(cfdp_user.eof_sent_call_count, 0);

        tb.put_request(&put_request)
            .expect("put_request call failed");
        assert_eq!(tb.handler.state(), State::Busy);
        assert_eq!(tb.handler.step(), TransactionStep::Idle);
        assert!(tb.get_next_sent_pdu().is_none());
        let id = tb.handler.transaction_id().unwrap();
        tb.handler
            .cancel_request(&mut cfdp_user, &id)
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
        let fault_handler = TestFaultHandler::default();
        let test_sender = TestCfdpSender::default();
        let mut tb = SourceHandlerTestbench::new(false, fault_handler, test_sender, 128);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&tb.srcfile)
            .expect("opening file failed");
        let mut rand_data = [0u8; 140];
        rand::thread_rng().fill(&mut rand_data[..]);
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
        let mut cfdp_user = tb.create_user(0, file_size);
        let transaction_info =
            tb.common_no_acked_file_transfer(&mut cfdp_user, put_request, file_size);
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
        assert!(tb
            .handler
            .cancel_request(&mut cfdp_user, &expected_id)
            .expect("cancellation failed"));
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
}
