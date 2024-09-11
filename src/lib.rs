//! This module contains the implementation of the CCSDS File Delivery Protocol (CFDP) high level
//! abstractions as specified in CCSDS 727.0-B-5.
//!
//! The basic idea of CFDP is to convert files of any size into a stream of packets called packet
//! data units (PDU). CFPD has an unacknowledged and acknowledged mode, with the option to request
//! a transaction closure for the unacknowledged mode. Using the unacknowledged mode with no
//! transaction closure is applicable for simplex communication paths, while the unacknowledged
//! mode with closure is the easiest way to get a confirmation of a successful file transfer,
//! including a CRC check on the remote side to verify file integrity. The acknowledged mode is
//! the most complex mode which includes multiple mechanism to ensure succesfull packet transaction
//! even for unreliable connections, including lost segment detection. As such, it can be compared
//! to a specialized TCP for file transfers with remote systems.
//!
//! The goal of this library is to be flexible enough to support the use-cases of both on-board
//! software and of ground software. It has support to make integration on [std] systems as simple
//! as possible, but also has sufficient abstraction to allow for integration on `no_std`
//! environments. Currently, the handlers still require the [std] feature until
//! [thiserror supports `error_in_core`](https://github.com/dtolnay/thiserror/pull/304).
//! It is recommended to activate the `alloc` feature at the very least to allow using the primary
//! components provided by this crate. These components will only allocate memory at initialization
//! time and thus are still viable for systems where run-time allocation is prohibited.
//!
//! The core of this library are the [crate::dest::DestinationHandler] and the
//! [crate::source::SourceHandler] components which model the CFDP destination and source entity
//! respectively. You can find high-level and API documentation for both handlers in the respective
//! [crate::dest] and [crate::source] module.
//!
//! # Examples
//!
//! This library currently features two example application which showcase how the provided
//! components could be used to provide CFDP services.
//!
//! The [end-to-end test](https://egit.irs.uni-stuttgart.de/rust/cfdp/src/branch/main/tests/end-to-end.rs)
//! is an integration tests which spawns a CFDP source entity and a CFDP destination entity,
//! moves them to separate threads and then performs a small file copy operation.
//! You can run the integration test for a transfer with no closure and with printout to the
//! standard console by running:
//!
//! ```sh
//! cargo test end_to_end_test_no_closure -- --nocapture
//! ```
//!
//! or with closure:
//!
//! ```sh
//! cargo test end_to_end_test_with_closure -- --nocapture
//! ```
//!
//! The [Python Interoperability](https://egit.irs.uni-stuttgart.de/rust/cfdp/src/branch/main/examples/python-interop)
//! example showcases the interoperability of the CFDP handlers written in Rust with a Python
//! implementation. The dedicated example documentation shows how to run this example.
//!
//! # Notes on the user hooks and scheduling
//!
//! Both examples feature implementations of the [UserFaultHookProvider] and the [user::CfdpUser]
//! trait which simply print some information to the console to monitor the progress of a file
//! copy operation. These implementations could be adapted for other handler integrations. For
//! example, they could signal a GUI application to display some information for the user.
//!
//! Even though both examples move the newly spawned handlers to dedicated threads, this is not
//! the only way they could be scheduled. For example, to support an arbitrary (or bounded)
//! amount of file copy operations on either source or destination side, those handlers could be
//! moved into a [std::collections::HashMap] structure which is then scheduled inside a thread, or
//! you could schedule a fixed amount of handlers inside a
//! [threadpool](https://docs.rs/threadpool/latest/threadpool/).
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "std")]
pub mod dest;
#[cfg(feature = "alloc")]
pub mod filestore;
pub mod request;
#[cfg(feature = "std")]
pub mod source;
pub mod time;
pub mod user;

use crate::time::CountdownProvider;
use core::{cell::RefCell, fmt::Debug, hash::Hash};
use crc::{Crc, CRC_32_ISCSI, CRC_32_ISO_HDLC};
#[cfg(feature = "std")]
use hashbrown::HashMap;

#[cfg(feature = "alloc")]
pub use alloc_mod::*;
use core::time::Duration;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use spacepackets::{
    cfdp::{
        pdu::{FileDirectiveType, PduError, PduHeader},
        ChecksumType, ConditionCode, FaultHandlerCode, PduType, TransmissionMode,
    },
    util::{UnsignedByteField, UnsignedEnum},
};
#[cfg(feature = "std")]
pub use std_mod::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EntityType {
    Sending,
    Receiving,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TimerContext {
    CheckLimit {
        local_id: UnsignedByteField,
        remote_id: UnsignedByteField,
        entity_type: EntityType,
    },
    NakActivity {
        expiry_time: Duration,
    },
    PositiveAck {
        expiry_time: Duration,
    },
}

/// A generic trait which allows CFDP entities to create check timers which are required to
/// implement special procedures in unacknowledged transmission mode, as specified in 4.6.3.2
/// and 4.6.3.3.
///
/// This trait also allows the creation of different check timers depending on context and purpose
/// of the timer, the runtime environment (e.g. standard clock timer vs. timer using a RTC) or
/// other factors.
///
/// The countdown timer is used by 3 mechanisms of the CFDP protocol.
///
/// ## 1. Check limit handling
///
/// The first mechanism is the check limit handling for unacknowledged transfers as specified
/// in 4.6.3.2 and 4.6.3.3 of the CFDP standard.
/// For this mechanism, the timer has different functionality depending on whether
/// the using entity is the sending entity or the receiving entity for the unacknowledged
/// transmission mode.
///
/// For the sending entity, this timer determines the expiry period for declaring a check limit
/// fault after sending an EOF PDU with requested closure. This allows a timeout of the transfer.
/// Also see 4.6.3.2 of the CFDP standard.
///
/// For the receiving entity, this timer determines the expiry period for incrementing a check
/// counter after an EOF PDU is received for an incomplete file transfer. This allows out-of-order
/// reception of file data PDUs and EOF PDUs. Also see 4.6.3.3 of the CFDP standard.
///
/// ## 2. NAK activity limit
///
/// The timer will be used to perform the NAK activity check as specified in 4.6.4.7 of the CFDP
/// standard. The expiration period will be provided by the NAK timer expiration limit of the
/// remote entity configuration.
///
/// ## 3. Positive ACK procedures
///
/// The timer will be used to perform the Positive Acknowledgement Procedures as specified in
/// 4.7. 1of the CFDP standard. The expiration period will be provided by the Positive ACK timer
/// interval of the remote entity configuration.
pub trait TimerCreatorProvider {
    type Countdown: CountdownProvider;

    fn create_countdown(&self, timer_context: TimerContext) -> Self::Countdown;
}

/// This structure models the remote entity configuration information as specified in chapter 8.3
/// of the CFDP standard.

/// Some of the fields which were not considered necessary for the Rust implementation
/// were omitted. Some other fields which are not contained inside the standard but are considered
/// necessary for the Rust implementation are included.
///
/// ## Notes on Positive Acknowledgment Procedures
///
/// The `positive_ack_timer_interval_seconds` and `positive_ack_timer_expiration_limit` will
/// be used for positive acknowledgement procedures as specified in CFDP chapter 4.7. The sending
/// entity will start the timer for any PDUs where an acknowledgment is required (e.g. EOF PDU).
/// Once the expected ACK response has not been received for that interval, as counter will be
/// incremented and the timer will be reset. Once the counter exceeds the
/// `positive_ack_timer_expiration_limit`, a Positive ACK Limit Reached fault will be declared.
///
/// ## Notes on Deferred Lost Segment Procedures
///
/// This procedure will be active if an EOF (No Error) PDU is received in acknowledged mode. After
/// issuing the NAK sequence which has the whole file scope, a timer will be started. The timer is
/// reset when missing segments or missing metadata is received. The timer will be deactivated if
/// all missing data is received. If the timer expires, a new NAK sequence will be issued and a
/// counter will be incremented, which can lead to a NAK Limit Reached fault being declared.
///
/// ## Fields
///
/// * `entity_id` - The ID of the remote entity.
/// * `max_packet_len` - This determines of all PDUs generated for that remote entity in addition
///    to the `max_file_segment_len` attribute which also determines the size of file data PDUs.
/// * `max_file_segment_len` The maximum file segment length which determines the maximum size
///   of file data PDUs in addition to the `max_packet_len` attribute. If this field is set
///   to None, the maximum file segment length will be derived from the maximum packet length.
///   If this has some value which is smaller than the segment value derived from
///   `max_packet_len`, this value will be picked.
/// * `closure_requested_by_default` - If the closure requested field is not supplied as part of
///    the Put Request, it will be determined from this field in the remote configuration.
/// * `crc_on_transmission_by_default` - If the CRC option is not supplied as part of the Put
///    Request, it will be determined from this field in the remote configuration.
/// * `default_transmission_mode` - If the transmission mode is not supplied as part of the
///   Put Request, it will be determined from this field in the remote configuration.
/// * `disposition_on_cancellation` - Determines whether an incomplete received file is discard on
///   transaction cancellation. Defaults to False.
/// * `default_crc_type` - Default checksum type used to calculate for all file transmissions to
///   this remote entity.
/// * `check_limit` - This timer determines the expiry period for incrementing a check counter
///   after an EOF PDU is received for an incomplete file transfer. This allows out-of-order
///   reception of file data PDUs and EOF PDUs. Also see 4.6.3.3 of the CFDP standard. Defaults to
///   2, so the check limit timer may expire twice.
/// * `positive_ack_timer_interval_seconds`- See the notes on the Positive Acknowledgment
///    Procedures inside the class documentation. Expected as floating point seconds. Defaults to
///    10 seconds.
/// * `positive_ack_timer_expiration_limit` - See the notes on the Positive Acknowledgment
///    Procedures inside the class documentation. Defaults to 2, so the timer may expire twice.
/// * `immediate_nak_mode` - Specifies whether a NAK sequence should be issued immediately when a
///    file data gap or lost metadata is detected in the acknowledged mode. Defaults to True.
/// * `nak_timer_interval_seconds` -  See the notes on the Deferred Lost Segment Procedure inside
///    the class documentation. Expected as floating point seconds. Defaults to 10 seconds.
/// * `nak_timer_expiration_limit` - See the notes on the Deferred Lost Segment Procedure inside
///    the class documentation. Defaults to 2, so the timer may expire two times.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RemoteEntityConfig {
    pub entity_id: UnsignedByteField,
    pub max_packet_len: usize,
    pub max_file_segment_len: Option<usize>,
    pub closure_requested_by_default: bool,
    pub crc_on_transmission_by_default: bool,
    pub default_transmission_mode: TransmissionMode,
    pub default_crc_type: ChecksumType,
    pub positive_ack_timer_interval_seconds: f32,
    pub positive_ack_timer_expiration_limit: u32,
    pub check_limit: u32,
    pub disposition_on_cancellation: bool,
    pub immediate_nak_mode: bool,
    pub nak_timer_interval_seconds: f32,
    pub nak_timer_expiration_limit: u32,
}

impl RemoteEntityConfig {
    pub fn new_with_default_values(
        entity_id: UnsignedByteField,
        max_packet_len: usize,
        closure_requested_by_default: bool,
        crc_on_transmission_by_default: bool,
        default_transmission_mode: TransmissionMode,
        default_crc_type: ChecksumType,
    ) -> Self {
        Self {
            entity_id,
            max_file_segment_len: None,
            max_packet_len,
            closure_requested_by_default,
            crc_on_transmission_by_default,
            default_transmission_mode,
            default_crc_type,
            check_limit: 2,
            positive_ack_timer_interval_seconds: 10.0,
            positive_ack_timer_expiration_limit: 2,
            disposition_on_cancellation: false,
            immediate_nak_mode: true,
            nak_timer_interval_seconds: 10.0,
            nak_timer_expiration_limit: 2,
        }
    }
}

pub trait RemoteEntityConfigProvider {
    /// Retrieve the remote entity configuration for the given remote ID.
    fn get(&self, remote_id: u64) -> Option<&RemoteEntityConfig>;
    fn get_mut(&mut self, remote_id: u64) -> Option<&mut RemoteEntityConfig>;
    /// Add a new remote configuration. Return [true] if the configuration was
    /// inserted successfully, and [false] if a configuration already exists.
    fn add_config(&mut self, cfg: &RemoteEntityConfig) -> bool;
    /// Remote a configuration. Returns [true] if the configuration was removed successfully,
    /// and [false] if no configuration exists for the given remote ID.
    fn remove_config(&mut self, remote_id: u64) -> bool;
}

/// This is a thin wrapper around a [HashMap] to store remote entity configurations.
/// It implements the full [RemoteEntityConfigProvider] trait.
#[cfg(feature = "std")]
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StdRemoteEntityConfigProvider(pub HashMap<u64, RemoteEntityConfig>);

#[cfg(feature = "std")]
impl RemoteEntityConfigProvider for StdRemoteEntityConfigProvider {
    fn get(&self, remote_id: u64) -> Option<&RemoteEntityConfig> {
        self.0.get(&remote_id)
    }
    fn get_mut(&mut self, remote_id: u64) -> Option<&mut RemoteEntityConfig> {
        self.0.get_mut(&remote_id)
    }
    fn add_config(&mut self, cfg: &RemoteEntityConfig) -> bool {
        self.0.insert(cfg.entity_id.value(), *cfg).is_some()
    }
    fn remove_config(&mut self, remote_id: u64) -> bool {
        self.0.remove(&remote_id).is_some()
    }
}

/// This is a thin wrapper around a [alloc::vec::Vec] to store remote entity configurations.
/// It implements the full [RemoteEntityConfigProvider] trait.
#[cfg(feature = "alloc")]
#[derive(Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VecRemoteEntityConfigProvider(pub alloc::vec::Vec<RemoteEntityConfig>);

#[cfg(feature = "alloc")]
impl RemoteEntityConfigProvider for VecRemoteEntityConfigProvider {
    fn get(&self, remote_id: u64) -> Option<&RemoteEntityConfig> {
        self.0
            .iter()
            .find(|&cfg| cfg.entity_id.value() == remote_id)
    }

    fn get_mut(&mut self, remote_id: u64) -> Option<&mut RemoteEntityConfig> {
        self.0
            .iter_mut()
            .find(|cfg| cfg.entity_id.value() == remote_id)
    }

    fn add_config(&mut self, cfg: &RemoteEntityConfig) -> bool {
        self.0.push(*cfg);
        true
    }

    fn remove_config(&mut self, remote_id: u64) -> bool {
        for (idx, cfg) in self.0.iter().enumerate() {
            if cfg.entity_id.value() == remote_id {
                self.0.remove(idx);
                return true;
            }
        }
        false
    }
}

/// A remote entity configurations also implements the [RemoteEntityConfigProvider], but the
/// [RemoteEntityConfigProvider::add_config] and [RemoteEntityConfigProvider::remove_config]
/// are no-ops and always returns [false].
impl RemoteEntityConfigProvider for RemoteEntityConfig {
    fn get(&self, remote_id: u64) -> Option<&RemoteEntityConfig> {
        if remote_id == self.entity_id.value() {
            return Some(self);
        }
        None
    }

    fn get_mut(&mut self, remote_id: u64) -> Option<&mut RemoteEntityConfig> {
        if remote_id == self.entity_id.value() {
            return Some(self);
        }
        None
    }

    fn add_config(&mut self, _cfg: &RemoteEntityConfig) -> bool {
        false
    }

    fn remove_config(&mut self, _remote_id: u64) -> bool {
        false
    }
}

/// This trait introduces some callbacks which will be called when a particular CFDP fault
/// handler is called.
///
/// It is passed into the CFDP handlers as part of the [UserFaultHookProvider] and the local entity
/// configuration and provides a way to specify custom user error handlers. This allows to
/// implement some CFDP features like fault handler logging, which would not be possible
/// generically otherwise.
///
/// For each error reported by the [FaultHandler], the appropriate fault handler callback
/// will be called depending on the [FaultHandlerCode].
pub trait UserFaultHookProvider {
    fn notice_of_suspension_cb(
        &mut self,
        transaction_id: TransactionId,
        cond: ConditionCode,
        progress: u64,
    );

    fn notice_of_cancellation_cb(
        &mut self,
        transaction_id: TransactionId,
        cond: ConditionCode,
        progress: u64,
    );

    fn abandoned_cb(&mut self, transaction_id: TransactionId, cond: ConditionCode, progress: u64);

    fn ignore_cb(&mut self, transaction_id: TransactionId, cond: ConditionCode, progress: u64);
}

/// Dummy fault hook which implements [UserFaultHookProvider] but only provides empty
/// implementations.
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct DummyFaultHook {}

impl UserFaultHookProvider for DummyFaultHook {
    fn notice_of_suspension_cb(
        &mut self,
        _transaction_id: TransactionId,
        _cond: ConditionCode,
        _progress: u64,
    ) {
    }

    fn notice_of_cancellation_cb(
        &mut self,
        _transaction_id: TransactionId,
        _cond: ConditionCode,
        _progress: u64,
    ) {
    }

    fn abandoned_cb(
        &mut self,
        _transaction_id: TransactionId,
        _cond: ConditionCode,
        _progress: u64,
    ) {
    }

    fn ignore_cb(&mut self, _transaction_id: TransactionId, _cond: ConditionCode, _progress: u64) {}
}

/// This structure is used to implement the fault handling as specified in chapter 4.8 of the CFDP
/// standard.
///
/// It does so by mapping each applicable [spacepackets::cfdp::ConditionCode] to a fault handler
/// which is denoted by the four [spacepackets::cfdp::FaultHandlerCode]s. This code is used
/// to select the error handling inside the CFDP handler itself in addition to dispatching to a
/// user-provided callback function provided by the [UserFaultHookProvider].
///
/// Some note on the provided default settings:
///
/// - Checksum failures will be ignored by default. This is because for unacknowledged transfers,
///   cancelling the transfer immediately would interfere with the check limit mechanism specified
///   in chapter 4.6.3.3.
/// - Unsupported checksum types will also be ignored by default. Even if the checksum type is
///   not supported the file transfer might still have worked properly.
///
/// For all other faults, the default fault handling operation will be to cancel the transaction.
/// These defaults can be overriden by using the [Self::set_fault_handler] method.
/// Please note that in any case, fault handler overrides can be specified by the sending CFDP
/// entity.
pub struct FaultHandler<UserHandler: UserFaultHookProvider> {
    handler_array: [FaultHandlerCode; 10],
    // Could also change the user fault handler trait to have non mutable methods, but that limits
    // flexbility on the user side..
    pub user_hook: RefCell<UserHandler>,
}

impl<UserHandler: UserFaultHookProvider> FaultHandler<UserHandler> {
    fn condition_code_to_array_index(conditon_code: ConditionCode) -> Option<usize> {
        Some(match conditon_code {
            ConditionCode::PositiveAckLimitReached => 0,
            ConditionCode::KeepAliveLimitReached => 1,
            ConditionCode::InvalidTransmissionMode => 2,
            ConditionCode::FilestoreRejection => 3,
            ConditionCode::FileChecksumFailure => 4,
            ConditionCode::FileSizeError => 5,
            ConditionCode::NakLimitReached => 6,
            ConditionCode::InactivityDetected => 7,
            ConditionCode::CheckLimitReached => 8,
            ConditionCode::UnsupportedChecksumType => 9,
            _ => return None,
        })
    }

    pub fn set_fault_handler(
        &mut self,
        condition_code: ConditionCode,
        fault_handler: FaultHandlerCode,
    ) {
        let array_idx = Self::condition_code_to_array_index(condition_code);
        if array_idx.is_none() {
            return;
        }
        self.handler_array[array_idx.unwrap()] = fault_handler;
    }

    pub fn new(user_fault_handler: UserHandler) -> Self {
        let mut init_array = [FaultHandlerCode::NoticeOfCancellation; 10];
        init_array
            [Self::condition_code_to_array_index(ConditionCode::FileChecksumFailure).unwrap()] =
            FaultHandlerCode::IgnoreError;
        init_array[Self::condition_code_to_array_index(ConditionCode::UnsupportedChecksumType)
            .unwrap()] = FaultHandlerCode::IgnoreError;
        Self {
            handler_array: init_array,
            user_hook: RefCell::new(user_fault_handler),
        }
    }

    pub fn get_fault_handler(&self, condition_code: ConditionCode) -> FaultHandlerCode {
        let array_idx = Self::condition_code_to_array_index(condition_code);
        if array_idx.is_none() {
            return FaultHandlerCode::IgnoreError;
        }
        self.handler_array[array_idx.unwrap()]
    }

    pub fn report_fault(
        &self,
        transaction_id: TransactionId,
        condition: ConditionCode,
        progress: u64,
    ) -> FaultHandlerCode {
        let array_idx = Self::condition_code_to_array_index(condition);
        if array_idx.is_none() {
            return FaultHandlerCode::IgnoreError;
        }
        let fh_code = self.handler_array[array_idx.unwrap()];
        let mut handler_mut = self.user_hook.borrow_mut();
        match fh_code {
            FaultHandlerCode::NoticeOfCancellation => {
                handler_mut.notice_of_cancellation_cb(transaction_id, condition, progress);
            }
            FaultHandlerCode::NoticeOfSuspension => {
                handler_mut.notice_of_suspension_cb(transaction_id, condition, progress);
            }
            FaultHandlerCode::IgnoreError => {
                handler_mut.ignore_cb(transaction_id, condition, progress);
            }
            FaultHandlerCode::AbandonTransaction => {
                handler_mut.abandoned_cb(transaction_id, condition, progress);
            }
        }
        fh_code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IndicationConfig {
    pub eof_sent: bool,
    pub eof_recv: bool,
    pub file_segment_recv: bool,
    pub transaction_finished: bool,
    pub suspended: bool,
    pub resumed: bool,
}

impl Default for IndicationConfig {
    fn default() -> Self {
        Self {
            eof_sent: true,
            eof_recv: true,
            file_segment_recv: true,
            transaction_finished: true,
            suspended: true,
            resumed: true,
        }
    }
}

/// Each CFDP entity handler has a [LocalEntityConfig]uration.
pub struct LocalEntityConfig<UserFaultHook: UserFaultHookProvider> {
    pub id: UnsignedByteField,
    pub indication_cfg: IndicationConfig,
    pub fault_handler: FaultHandler<UserFaultHook>,
}

impl<UserFaultHook: UserFaultHookProvider> LocalEntityConfig<UserFaultHook> {
    pub fn new(
        id: UnsignedByteField,
        indication_cfg: IndicationConfig,
        hook: UserFaultHook,
    ) -> Self {
        Self {
            id,
            indication_cfg,
            fault_handler: FaultHandler::new(hook),
        }
    }
}

impl<UserFaultHook: UserFaultHookProvider> LocalEntityConfig<UserFaultHook> {
    pub fn user_fault_hook_mut(&mut self) -> &mut RefCell<UserFaultHook> {
        &mut self.fault_handler.user_hook
    }

    pub fn user_fault_hook(&self) -> &RefCell<UserFaultHook> {
        &self.fault_handler.user_hook
    }
}

/// Generic error type for sending a PDU via a message queue.
#[cfg(feature = "std")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GenericSendError {
    #[error("RX disconnected")]
    RxDisconnected,
    #[error("queue is full, fill count {0:?}")]
    QueueFull(Option<u32>),
    #[error("other send error")]
    Other,
}

#[cfg(feature = "std")]
pub trait PduSendProvider {
    fn send_pdu(
        &self,
        pdu_type: PduType,
        file_directive_type: Option<FileDirectiveType>,
        raw_pdu: &[u8],
    ) -> Result<(), GenericSendError>;
}

#[cfg(feature = "std")]
pub mod std_mod {
    use std::sync::mpsc;

    use super::*;

    impl PduSendProvider for mpsc::Sender<PduOwnedWithInfo> {
        fn send_pdu(
            &self,
            pdu_type: PduType,
            file_directive_type: Option<FileDirectiveType>,
            raw_pdu: &[u8],
        ) -> Result<(), GenericSendError> {
            self.send(PduOwnedWithInfo::new(
                pdu_type,
                file_directive_type,
                raw_pdu.to_vec(),
            ))
            .map_err(|_| GenericSendError::RxDisconnected)?;
            Ok(())
        }
    }

    /// Simple implementation of the [CountdownProvider] trait assuming a standard runtime.
    #[derive(Debug)]
    pub struct StdCountdown {
        expiry_time: Duration,
        start_time: std::time::Instant,
    }

    impl StdCountdown {
        pub fn new(expiry_time: Duration) -> Self {
            Self {
                expiry_time,
                start_time: std::time::Instant::now(),
            }
        }

        pub fn expiry_time_seconds(&self) -> u64 {
            self.expiry_time.as_secs()
        }
    }

    impl CountdownProvider for StdCountdown {
        fn has_expired(&self) -> bool {
            if self.start_time.elapsed() > self.expiry_time {
                return true;
            }
            false
        }

        fn reset(&mut self) {
            self.start_time = std::time::Instant::now();
        }
    }

    pub struct StdTimerCreator {
        pub check_limit_timeout: Duration,
    }

    impl StdTimerCreator {
        pub const fn new(check_limit_timeout: Duration) -> Self {
            Self {
                check_limit_timeout,
            }
        }
    }

    impl Default for StdTimerCreator {
        fn default() -> Self {
            Self::new(Duration::from_secs(5))
        }
    }

    impl TimerCreatorProvider for StdTimerCreator {
        type Countdown = StdCountdown;

        fn create_countdown(&self, timer_context: TimerContext) -> Self::Countdown {
            match timer_context {
                TimerContext::CheckLimit {
                    local_id: _,
                    remote_id: _,
                    entity_type: _,
                } => StdCountdown::new(self.check_limit_timeout),
                TimerContext::NakActivity { expiry_time } => StdCountdown::new(expiry_time),
                TimerContext::PositiveAck { expiry_time } => StdCountdown::new(expiry_time),
            }
        }
    }
}

/// The CFDP transaction ID of a CFDP transaction consists of the source entity ID and the sequence
/// number of that transfer which is also determined by the CFDP source entity.
#[derive(Debug, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransactionId {
    source_id: UnsignedByteField,
    seq_num: UnsignedByteField,
}

impl TransactionId {
    pub fn new(source_id: UnsignedByteField, seq_num: UnsignedByteField) -> Self {
        Self { source_id, seq_num }
    }

    pub fn source_id(&self) -> &UnsignedByteField {
        &self.source_id
    }

    pub fn seq_num(&self) -> &UnsignedByteField {
        &self.seq_num
    }
}

impl Hash for TransactionId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.source_id.value().hash(state);
        self.seq_num.value().hash(state);
    }
}

impl PartialEq for TransactionId {
    fn eq(&self, other: &Self) -> bool {
        self.source_id.value() == other.source_id.value()
            && self.seq_num.value() == other.seq_num.value()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum State {
    Idle = 0,
    Busy = 1,
    Suspended = 2,
}

/// [crc::Crc] instance using [crc::CRC_32_ISO_HDLC].
///
/// SANA registry entry: <https://sanaregistry.org/r/checksum_identifiers/records/4>,
/// Entry in CRC catalogue: <https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-32>
pub const CRC_32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
/// [crc::Crc] instance using [crc::CRC_32_ISCSI].
///
/// SANA registry entry: <https://sanaregistry.org/r/checksum_identifiers/records/3>,
/// Entry in CRC catalogue: <https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-32-iscsi>
pub const CRC_32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PacketTarget {
    SourceEntity,
    DestEntity,
}

/// Generic trait which models a raw CFDP packet data unit (PDU) block with some additional context
/// information.
pub trait PduProvider {
    fn pdu_type(&self) -> PduType;
    fn file_directive_type(&self) -> Option<FileDirectiveType>;
    fn pdu(&self) -> &[u8];
    fn packet_target(&self) -> Result<PacketTarget, PduError>;
}

pub struct DummyPduProvider(());

impl PduProvider for DummyPduProvider {
    fn pdu_type(&self) -> PduType {
        PduType::FileData
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        None
    }

    fn pdu(&self) -> &[u8] {
        &[]
    }

    fn packet_target(&self) -> Result<PacketTarget, PduError> {
        Ok(PacketTarget::SourceEntity)
    }
}

/// This is a helper struct which contains base information about a particular PDU packet.
/// This is also necessary information for CFDP packet routing. For example, some packet types
/// like file data PDUs can only be used by CFDP source entities.
pub struct PduRawWithInfo<'raw_packet> {
    pdu_type: PduType,
    file_directive_type: Option<FileDirectiveType>,
    packet_len: usize,
    raw_packet: &'raw_packet [u8],
}

pub fn determine_packet_target(raw_pdu: &[u8]) -> Result<PacketTarget, PduError> {
    let (header, header_len) = PduHeader::from_bytes(raw_pdu)?;
    if header.pdu_type() == PduType::FileData {
        return Ok(PacketTarget::DestEntity);
    }
    let file_directive_type = FileDirectiveType::try_from(raw_pdu[header_len]).map_err(|_| {
        PduError::InvalidDirectiveType {
            found: raw_pdu[header_len],
            expected: None,
        }
    })?;
    let packet_target =
        match file_directive_type {
            // Section c) of 4.5.3: These PDUs should always be targeted towards the file sender a.k.a.
            // the source handler
            FileDirectiveType::NakPdu
            | FileDirectiveType::FinishedPdu
            | FileDirectiveType::KeepAlivePdu => PacketTarget::SourceEntity,
            // Section b) of 4.5.3: These PDUs should always be targeted towards the file receiver a.k.a.
            // the destination handler
            FileDirectiveType::MetadataPdu
            | FileDirectiveType::EofPdu
            | FileDirectiveType::PromptPdu => PacketTarget::DestEntity,
            // Section a): Recipient depends of the type of PDU that is being acknowledged. We can simply
            // extract the PDU type from the raw stream. If it is an EOF PDU, this packet is passed to
            // the source handler, for a Finished PDU, it is passed to the destination handler.
            FileDirectiveType::AckPdu => {
                let acked_directive = FileDirectiveType::try_from(raw_pdu[header_len + 1])
                    .map_err(|_| PduError::InvalidDirectiveType {
                        found: raw_pdu[header_len],
                        expected: None,
                    })?;
                if acked_directive == FileDirectiveType::EofPdu {
                    PacketTarget::SourceEntity
                } else if acked_directive == FileDirectiveType::FinishedPdu {
                    PacketTarget::DestEntity
                } else {
                    // TODO: Maybe a better error? This might be confusing..
                    return Err(PduError::InvalidDirectiveType {
                        found: raw_pdu[header_len + 1],
                        expected: None,
                    });
                }
            }
        };
    Ok(packet_target)
}

impl<'raw> PduRawWithInfo<'raw> {
    pub fn new(raw_packet: &'raw [u8]) -> Result<Self, PduError> {
        let (pdu_header, header_len) = PduHeader::from_bytes(raw_packet)?;
        if pdu_header.pdu_type() == PduType::FileData {
            return Ok(Self {
                pdu_type: pdu_header.pdu_type(),
                file_directive_type: None,
                packet_len: pdu_header.pdu_len(),
                raw_packet,
            });
        }
        if pdu_header.pdu_datafield_len() < 1 {
            return Err(PduError::FormatError);
        }
        // Route depending on PDU type and directive type if applicable. Retrieve directive type
        // from the raw stream for better performance (with sanity and directive code check).
        // The routing is based on section 4.5 of the CFDP standard which specifies the PDU forwarding
        // procedure.
        let directive = FileDirectiveType::try_from(raw_packet[header_len]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: raw_packet[header_len],
                expected: None,
            }
        })?;
        Ok(Self {
            pdu_type: pdu_header.pdu_type(),
            file_directive_type: Some(directive),
            packet_len: pdu_header.pdu_len(),
            raw_packet,
        })
    }

    pub fn raw_packet(&self) -> &[u8] {
        &self.raw_packet[0..self.packet_len]
    }
}

impl PduProvider for PduRawWithInfo<'_> {
    fn pdu_type(&self) -> PduType {
        self.pdu_type
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        self.file_directive_type
    }

    fn pdu(&self) -> &[u8] {
        self.raw_packet
    }

    fn packet_target(&self) -> Result<PacketTarget, PduError> {
        determine_packet_target(self.raw_packet)
    }
}

#[cfg(feature = "alloc")]
pub mod alloc_mod {
    use spacepackets::cfdp::{
        pdu::{FileDirectiveType, PduError},
        PduType,
    };

    use crate::{determine_packet_target, PacketTarget, PduProvider, PduRawWithInfo};

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct PduOwnedWithInfo {
        pub pdu_type: PduType,
        pub file_directive_type: Option<FileDirectiveType>,
        pub pdu: alloc::vec::Vec<u8>,
    }

    impl PduOwnedWithInfo {
        pub fn new_from_raw_packet(raw_packet: &[u8]) -> Result<Self, PduError> {
            Ok(PduRawWithInfo::new(raw_packet)?.into())
        }

        pub fn new(
            pdu_type: PduType,
            file_directive_type: Option<FileDirectiveType>,
            pdu: alloc::vec::Vec<u8>,
        ) -> Self {
            Self {
                pdu_type,
                file_directive_type,
                pdu,
            }
        }
    }

    impl From<PduRawWithInfo<'_>> for PduOwnedWithInfo {
        fn from(value: PduRawWithInfo) -> Self {
            Self::new(
                value.pdu_type(),
                value.file_directive_type(),
                value.raw_packet().to_vec(),
            )
        }
    }

    impl PduProvider for PduOwnedWithInfo {
        fn pdu_type(&self) -> PduType {
            self.pdu_type
        }

        fn file_directive_type(&self) -> Option<FileDirectiveType> {
            self.file_directive_type
        }

        fn pdu(&self) -> &[u8] {
            &self.pdu
        }

        fn packet_target(&self) -> Result<PacketTarget, PduError> {
            determine_packet_target(&self.pdu)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::cell::RefCell;

    use alloc::{collections::VecDeque, string::String, vec::Vec};
    use spacepackets::{
        cfdp::{
            lv::Lv,
            pdu::{
                eof::EofPdu,
                file_data::FileDataPdu,
                metadata::{MetadataGenericParams, MetadataPduCreator},
                CommonPduConfig, FileDirectiveType, PduHeader, WritablePduPacket,
            },
            ChecksumType, ConditionCode, PduType, TransmissionMode,
        },
        util::{UnsignedByteField, UnsignedByteFieldU16, UnsignedByteFieldU8, UnsignedEnum},
    };
    use user::{CfdpUser, OwnedMetadataRecvdParams, TransactionFinishedParams};

    use crate::{PacketTarget, StdCountdown};

    use super::*;

    pub const LOCAL_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(1);
    pub const REMOTE_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(2);

    pub struct FileSegmentRecvdParamsNoSegMetadata {
        #[allow(dead_code)]
        pub id: TransactionId,
        pub offset: u64,
        pub length: usize,
    }

    #[derive(Default)]
    pub struct TestCfdpUser {
        pub next_expected_seq_num: u64,
        pub expected_full_src_name: String,
        pub expected_full_dest_name: String,
        pub expected_file_size: u64,
        pub transaction_indication_call_count: u32,
        pub eof_sent_call_count: u32,
        pub eof_recvd_call_count: u32,
        pub finished_indic_queue: VecDeque<TransactionFinishedParams>,
        pub metadata_recv_queue: VecDeque<OwnedMetadataRecvdParams>,
        pub file_seg_recvd_queue: VecDeque<FileSegmentRecvdParamsNoSegMetadata>,
    }

    impl TestCfdpUser {
        pub fn new(
            next_expected_seq_num: u64,
            expected_full_src_name: String,
            expected_full_dest_name: String,
            expected_file_size: u64,
        ) -> Self {
            Self {
                next_expected_seq_num,
                expected_full_src_name,
                expected_full_dest_name,
                expected_file_size,
                transaction_indication_call_count: 0,
                eof_recvd_call_count: 0,
                eof_sent_call_count: 0,
                finished_indic_queue: VecDeque::new(),
                metadata_recv_queue: VecDeque::new(),
                file_seg_recvd_queue: VecDeque::new(),
            }
        }

        pub fn generic_id_check(&self, id: &crate::TransactionId) {
            assert_eq!(id.source_id, LOCAL_ID.into());
            assert_eq!(id.seq_num().value(), self.next_expected_seq_num);
        }
    }

    impl CfdpUser for TestCfdpUser {
        fn transaction_indication(&mut self, id: &crate::TransactionId) {
            self.generic_id_check(id);
            self.transaction_indication_call_count += 1;
        }

        fn eof_sent_indication(&mut self, id: &crate::TransactionId) {
            self.generic_id_check(id);
            self.eof_sent_call_count += 1;
        }

        fn transaction_finished_indication(
            &mut self,
            finished_params: &crate::user::TransactionFinishedParams,
        ) {
            self.generic_id_check(&finished_params.id);
            self.finished_indic_queue.push_back(*finished_params);
        }

        fn metadata_recvd_indication(
            &mut self,
            md_recvd_params: &crate::user::MetadataReceivedParams,
        ) {
            self.generic_id_check(&md_recvd_params.id);
            assert_eq!(
                String::from(md_recvd_params.src_file_name),
                self.expected_full_src_name
            );
            assert_eq!(
                String::from(md_recvd_params.dest_file_name),
                self.expected_full_dest_name
            );
            assert_eq!(md_recvd_params.msgs_to_user.len(), 0);
            assert_eq!(md_recvd_params.source_id, LOCAL_ID.into());
            assert_eq!(md_recvd_params.file_size, self.expected_file_size);
            self.metadata_recv_queue.push_back(md_recvd_params.into());
        }

        fn file_segment_recvd_indication(
            &mut self,
            segment_recvd_params: &crate::user::FileSegmentRecvdParams,
        ) {
            self.generic_id_check(&segment_recvd_params.id);
            self.file_seg_recvd_queue
                .push_back(FileSegmentRecvdParamsNoSegMetadata {
                    id: segment_recvd_params.id,
                    offset: segment_recvd_params.offset,
                    length: segment_recvd_params.length,
                })
        }

        fn report_indication(&mut self, _id: &crate::TransactionId) {}

        fn suspended_indication(
            &mut self,
            _id: &crate::TransactionId,
            _condition_code: ConditionCode,
        ) {
            panic!("unexpected suspended indication");
        }

        fn resumed_indication(&mut self, _id: &crate::TransactionId, _progresss: u64) {}

        fn fault_indication(
            &mut self,
            _id: &crate::TransactionId,
            _condition_code: ConditionCode,
            _progress: u64,
        ) {
            panic!("unexpected fault indication");
        }

        fn abandoned_indication(
            &mut self,
            _id: &crate::TransactionId,
            _condition_code: ConditionCode,
            _progress: u64,
        ) {
            panic!("unexpected abandoned indication");
        }

        fn eof_recvd_indication(&mut self, id: &crate::TransactionId) {
            self.generic_id_check(id);
            self.eof_recvd_call_count += 1;
        }
    }

    #[derive(Default, Debug)]
    pub(crate) struct TestFaultHandler {
        pub notice_of_suspension_queue: VecDeque<(TransactionId, ConditionCode, u64)>,
        pub notice_of_cancellation_queue: VecDeque<(TransactionId, ConditionCode, u64)>,
        pub abandoned_queue: VecDeque<(TransactionId, ConditionCode, u64)>,
        pub ignored_queue: VecDeque<(TransactionId, ConditionCode, u64)>,
    }

    impl UserFaultHookProvider for TestFaultHandler {
        fn notice_of_suspension_cb(
            &mut self,
            transaction_id: TransactionId,
            cond: ConditionCode,
            progress: u64,
        ) {
            self.notice_of_suspension_queue
                .push_back((transaction_id, cond, progress))
        }

        fn notice_of_cancellation_cb(
            &mut self,
            transaction_id: TransactionId,
            cond: ConditionCode,
            progress: u64,
        ) {
            self.notice_of_cancellation_queue
                .push_back((transaction_id, cond, progress))
        }

        fn abandoned_cb(
            &mut self,
            transaction_id: TransactionId,
            cond: ConditionCode,
            progress: u64,
        ) {
            self.abandoned_queue
                .push_back((transaction_id, cond, progress))
        }

        fn ignore_cb(&mut self, transaction_id: TransactionId, cond: ConditionCode, progress: u64) {
            self.ignored_queue
                .push_back((transaction_id, cond, progress))
        }
    }

    impl TestFaultHandler {
        pub(crate) fn suspension_queue_empty(&self) -> bool {
            self.notice_of_suspension_queue.is_empty()
        }
        pub(crate) fn cancellation_queue_empty(&self) -> bool {
            self.notice_of_cancellation_queue.is_empty()
        }
        pub(crate) fn ignored_queue_empty(&self) -> bool {
            self.ignored_queue.is_empty()
        }
        pub(crate) fn abandoned_queue_empty(&self) -> bool {
            self.abandoned_queue.is_empty()
        }
        pub(crate) fn all_queues_empty(&self) -> bool {
            self.suspension_queue_empty()
                && self.cancellation_queue_empty()
                && self.ignored_queue_empty()
                && self.abandoned_queue_empty()
        }
    }

    pub struct SentPdu {
        pub pdu_type: PduType,
        pub file_directive_type: Option<FileDirectiveType>,
        pub raw_pdu: Vec<u8>,
    }

    #[derive(Default)]
    pub struct TestCfdpSender {
        pub packet_queue: RefCell<VecDeque<SentPdu>>,
    }

    impl PduSendProvider for TestCfdpSender {
        fn send_pdu(
            &self,
            pdu_type: PduType,
            file_directive_type: Option<FileDirectiveType>,
            raw_pdu: &[u8],
        ) -> Result<(), GenericSendError> {
            self.packet_queue.borrow_mut().push_back(SentPdu {
                pdu_type,
                file_directive_type,
                raw_pdu: raw_pdu.to_vec(),
            });
            Ok(())
        }
    }

    impl TestCfdpSender {
        pub fn retrieve_next_pdu(&self) -> Option<SentPdu> {
            self.packet_queue.borrow_mut().pop_front()
        }
        pub fn queue_empty(&self) -> bool {
            self.packet_queue.borrow_mut().is_empty()
        }
    }

    pub fn basic_remote_cfg_table(
        dest_id: impl Into<UnsignedByteField>,
        max_packet_len: usize,
        crc_on_transmission_by_default: bool,
    ) -> StdRemoteEntityConfigProvider {
        let mut table = StdRemoteEntityConfigProvider::default();
        let remote_entity_cfg = RemoteEntityConfig::new_with_default_values(
            dest_id.into(),
            max_packet_len,
            true,
            crc_on_transmission_by_default,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        table.add_config(&remote_entity_cfg);
        table
    }

    fn generic_pdu_header() -> PduHeader {
        let pdu_conf = CommonPduConfig::default();
        PduHeader::new_no_file_data(pdu_conf, 0)
    }

    #[test]
    fn test_transaction_id() {
        let transaction_id = TransactionId::new(
            UnsignedByteFieldU16::new(1).into(),
            UnsignedByteFieldU16::new(2).into(),
        );
        assert_eq!(transaction_id.source_id().value(), 1);
        assert_eq!(transaction_id.seq_num().value(), 2);
    }

    #[test]
    fn test_metadata_pdu_info() {
        let mut buf: [u8; 128] = [0; 128];
        let pdu_header = generic_pdu_header();
        let metadata_params = MetadataGenericParams::default();
        let src_file_name = "hello.txt";
        let dest_file_name = "hello-dest.txt";
        let src_lv = Lv::new_from_str(src_file_name).unwrap();
        let dest_lv = Lv::new_from_str(dest_file_name).unwrap();
        let metadata_pdu =
            MetadataPduCreator::new_no_opts(pdu_header, metadata_params, src_lv, dest_lv);
        metadata_pdu
            .write_to_bytes(&mut buf)
            .expect("writing metadata PDU failed");

        let packet_info = PduRawWithInfo::new(&buf).expect("creating packet info failed");
        assert_eq!(packet_info.pdu_type(), PduType::FileDirective);
        assert!(packet_info.file_directive_type().is_some());
        assert_eq!(
            packet_info.file_directive_type().unwrap(),
            FileDirectiveType::MetadataPdu
        );
        assert_eq!(
            packet_info.raw_packet(),
            &buf[0..metadata_pdu.len_written()]
        );
        assert_eq!(
            packet_info.packet_target().unwrap(),
            PacketTarget::DestEntity
        );
    }

    #[test]
    fn test_filedata_pdu_info() {
        let mut buf: [u8; 128] = [0; 128];
        let pdu_header = generic_pdu_header();
        let file_data_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 0, &[]);
        file_data_pdu
            .write_to_bytes(&mut buf)
            .expect("writing file data PDU failed");
        let packet_info = PduRawWithInfo::new(&buf).expect("creating packet info failed");
        assert_eq!(
            packet_info.raw_packet(),
            &buf[0..file_data_pdu.len_written()]
        );
        assert_eq!(packet_info.pdu_type(), PduType::FileData);
        assert!(packet_info.file_directive_type().is_none());
        assert_eq!(
            packet_info.packet_target().unwrap(),
            PacketTarget::DestEntity
        );
    }

    #[test]
    fn test_eof_pdu_info() {
        let mut buf: [u8; 128] = [0; 128];
        let pdu_header = generic_pdu_header();
        let eof_pdu = EofPdu::new_no_error(pdu_header, 0, 0);
        eof_pdu
            .write_to_bytes(&mut buf)
            .expect("writing file data PDU failed");
        let packet_info = PduRawWithInfo::new(&buf).expect("creating packet info failed");
        assert_eq!(packet_info.pdu_type(), PduType::FileDirective);
        assert!(packet_info.file_directive_type().is_some());
        assert_eq!(packet_info.raw_packet(), &buf[0..eof_pdu.len_written()]);
        assert_eq!(
            packet_info.file_directive_type().unwrap(),
            FileDirectiveType::EofPdu
        );
    }

    #[test]
    fn test_std_check_timer() {
        let mut std_check_timer = StdCountdown::new(Duration::from_secs(1));
        assert!(!std_check_timer.has_expired());
        assert_eq!(std_check_timer.expiry_time_seconds(), 1);
        std::thread::sleep(Duration::from_millis(800));
        assert!(!std_check_timer.has_expired());
        std::thread::sleep(Duration::from_millis(205));
        assert!(std_check_timer.has_expired());
        std_check_timer.reset();
        assert!(!std_check_timer.has_expired());
    }

    #[test]
    fn test_std_check_timer_creator() {
        let std_check_timer_creator = StdTimerCreator::new(Duration::from_secs(1));
        let check_timer = std_check_timer_creator.create_countdown(TimerContext::NakActivity {
            expiry_time: Duration::from_secs(1),
        });
        assert_eq!(check_timer.expiry_time_seconds(), 1);
    }

    #[test]
    fn test_remote_cfg_provider_single() {
        let mut remote_entity_cfg = RemoteEntityConfig::new_with_default_values(
            REMOTE_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        let remote_entity_retrieved = remote_entity_cfg.get(REMOTE_ID.value()).unwrap();
        assert_eq!(remote_entity_retrieved.entity_id, REMOTE_ID.into());
        assert_eq!(remote_entity_retrieved.max_packet_len, 1024);
        assert!(remote_entity_retrieved.closure_requested_by_default);
        assert!(!remote_entity_retrieved.crc_on_transmission_by_default);
        assert_eq!(
            remote_entity_retrieved.default_crc_type,
            ChecksumType::Crc32
        );
        let remote_entity_mut = remote_entity_cfg.get_mut(REMOTE_ID.value()).unwrap();
        assert_eq!(remote_entity_mut.entity_id, REMOTE_ID.into());
        let dummy = RemoteEntityConfig::new_with_default_values(
            LOCAL_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        assert!(!remote_entity_cfg.add_config(&dummy));
        // Removal is no-op.
        assert!(!remote_entity_cfg.remove_config(REMOTE_ID.value()));
        let remote_entity_retrieved = remote_entity_cfg.get(REMOTE_ID.value()).unwrap();
        assert_eq!(remote_entity_retrieved.entity_id, REMOTE_ID.into());
        // Does not exist.
        assert!(remote_entity_cfg.get(LOCAL_ID.value()).is_none());
        assert!(remote_entity_cfg.get_mut(LOCAL_ID.value()).is_none());
    }

    #[test]
    fn test_remote_cfg_provider_std() {
        let remote_entity_cfg = RemoteEntityConfig::new_with_default_values(
            REMOTE_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        let mut remote_cfg_provider = StdRemoteEntityConfigProvider::default();
        assert!(remote_cfg_provider.0.is_empty());
        remote_cfg_provider.add_config(&remote_entity_cfg);
        assert_eq!(remote_cfg_provider.0.len(), 1);
        let remote_entity_cfg_2 = RemoteEntityConfig::new_with_default_values(
            LOCAL_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        let cfg_0 = remote_cfg_provider.get(REMOTE_ID.value()).unwrap();
        assert_eq!(cfg_0.entity_id, REMOTE_ID.into());
        remote_cfg_provider.add_config(&remote_entity_cfg_2);
        assert_eq!(remote_cfg_provider.0.len(), 2);
        let cfg_1 = remote_cfg_provider.get(LOCAL_ID.value()).unwrap();
        assert_eq!(cfg_1.entity_id, LOCAL_ID.into());
        assert!(remote_cfg_provider.remove_config(REMOTE_ID.value()));
        assert_eq!(remote_cfg_provider.0.len(), 1);
        let cfg_1_mut = remote_cfg_provider.get_mut(LOCAL_ID.value()).unwrap();
        cfg_1_mut.default_crc_type = ChecksumType::Crc32C;
        assert!(!remote_cfg_provider.remove_config(REMOTE_ID.value()));
        assert!(remote_cfg_provider.get_mut(REMOTE_ID.value()).is_none());
    }

    #[test]
    fn test_remote_cfg_provider_vector() {
        let mut remote_cfg_provider = VecRemoteEntityConfigProvider::default();
        let remote_entity_cfg = RemoteEntityConfig::new_with_default_values(
            REMOTE_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        assert!(remote_cfg_provider.0.is_empty());
        remote_cfg_provider.add_config(&remote_entity_cfg);
        assert_eq!(remote_cfg_provider.0.len(), 1);
        let remote_entity_cfg_2 = RemoteEntityConfig::new_with_default_values(
            LOCAL_ID.into(),
            1024,
            true,
            false,
            TransmissionMode::Unacknowledged,
            ChecksumType::Crc32,
        );
        let cfg_0 = remote_cfg_provider.get(REMOTE_ID.value()).unwrap();
        assert_eq!(cfg_0.entity_id, REMOTE_ID.into());
        remote_cfg_provider.add_config(&remote_entity_cfg_2);
        assert_eq!(remote_cfg_provider.0.len(), 2);
        let cfg_1 = remote_cfg_provider.get(LOCAL_ID.value()).unwrap();
        assert_eq!(cfg_1.entity_id, LOCAL_ID.into());
        assert!(remote_cfg_provider.remove_config(REMOTE_ID.value()));
        assert_eq!(remote_cfg_provider.0.len(), 1);
        let cfg_1_mut = remote_cfg_provider.get_mut(LOCAL_ID.value()).unwrap();
        cfg_1_mut.default_crc_type = ChecksumType::Crc32C;
        assert!(!remote_cfg_provider.remove_config(REMOTE_ID.value()));
        assert!(remote_cfg_provider.get_mut(REMOTE_ID.value()).is_none());
    }

    #[test]
    fn dummy_fault_hook_test() {
        let mut user_hook_dummy = DummyFaultHook::default();
        let transaction_id = TransactionId::new(
            UnsignedByteFieldU8::new(0).into(),
            UnsignedByteFieldU8::new(0).into(),
        );
        user_hook_dummy.notice_of_cancellation_cb(transaction_id, ConditionCode::NoError, 0);
        user_hook_dummy.notice_of_suspension_cb(transaction_id, ConditionCode::NoError, 0);
        user_hook_dummy.abandoned_cb(transaction_id, ConditionCode::NoError, 0);
        user_hook_dummy.ignore_cb(transaction_id, ConditionCode::NoError, 0);
    }

    #[test]
    fn dummy_pdu_provider_test() {
        let dummy_pdu_provider = DummyPduProvider(());
        assert_eq!(dummy_pdu_provider.pdu_type(), PduType::FileData);
        assert!(dummy_pdu_provider.file_directive_type().is_none());
        assert_eq!(dummy_pdu_provider.pdu(), &[]);
        assert_eq!(
            dummy_pdu_provider.packet_target(),
            Ok(PacketTarget::SourceEntity)
        );
    }

    #[test]
    fn test_fault_handler_checksum_error_ignored_by_default() {
        let fault_handler = FaultHandler::new(TestFaultHandler::default());
        assert_eq!(
            fault_handler.get_fault_handler(ConditionCode::FileChecksumFailure),
            FaultHandlerCode::IgnoreError
        );
    }

    #[test]
    fn test_fault_handler_unsupported_checksum_ignored_by_default() {
        let fault_handler = FaultHandler::new(TestFaultHandler::default());
        assert_eq!(
            fault_handler.get_fault_handler(ConditionCode::UnsupportedChecksumType),
            FaultHandlerCode::IgnoreError
        );
    }

    #[test]
    fn test_fault_handler_basic() {
        let mut fault_handler = FaultHandler::new(TestFaultHandler::default());
        assert_eq!(
            fault_handler.get_fault_handler(ConditionCode::FileChecksumFailure),
            FaultHandlerCode::IgnoreError
        );
        fault_handler.set_fault_handler(
            ConditionCode::FileChecksumFailure,
            FaultHandlerCode::NoticeOfCancellation,
        );
        assert_eq!(
            fault_handler.get_fault_handler(ConditionCode::FileChecksumFailure),
            FaultHandlerCode::NoticeOfCancellation
        );
    }

    #[test]
    fn transaction_id_hashable_usable_as_map_key() {
        let mut map = HashMap::new();
        let transaction_id_0 = TransactionId::new(
            UnsignedByteFieldU8::new(1).into(),
            UnsignedByteFieldU8::new(2).into(),
        );
        map.insert(transaction_id_0, 5_u32);
    }
}
