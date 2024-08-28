//! This is an end-to-end integration tests using the CFDP abstractions provided by the library.
use std::{
    fs::OpenOptions,
    io::Write,
    sync::{atomic::AtomicBool, mpsc, Arc},
    thread,
    time::Duration,
};

use cfdp::{
    dest::DestinationHandler,
    filestore::NativeFilestore,
    request::{PutRequestOwned, StaticPutRequestCacher},
    source::SourceHandler,
    user::{CfdpUser, FileSegmentRecvdParams, MetadataReceivedParams, TransactionFinishedParams},
    EntityType, IndicationConfig, LocalEntityConfig, PduOwnedWithInfo, RemoteEntityConfig,
    StdCheckTimerCreator, TransactionId, UserFaultHookProvider,
};
use spacepackets::{
    cfdp::{ChecksumType, ConditionCode, TransmissionMode},
    seq_count::SeqCountProviderSyncU16,
    util::UnsignedByteFieldU16,
};

const LOCAL_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(1);
const REMOTE_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(2);

const FILE_DATA: &str = "Hello World!";

#[derive(Default)]
pub struct ExampleFaultHandler {}

impl UserFaultHookProvider for ExampleFaultHandler {
    fn notice_of_suspension_cb(
        &mut self,
        transaction_id: TransactionId,
        cond: ConditionCode,
        progress: u64,
    ) {
        panic!(
            "unexpected suspension of transaction {:?}, condition code {:?}, progress {}",
            transaction_id, cond, progress
        );
    }

    fn notice_of_cancellation_cb(
        &mut self,
        transaction_id: TransactionId,
        cond: ConditionCode,
        progress: u64,
    ) {
        panic!(
            "unexpected cancellation of transaction {:?}, condition code {:?}, progress {}",
            transaction_id, cond, progress
        );
    }

    fn abandoned_cb(&mut self, transaction_id: TransactionId, cond: ConditionCode, progress: u64) {
        panic!(
            "unexpected abandonment of transaction {:?}, condition code {:?}, progress {}",
            transaction_id, cond, progress
        );
    }

    fn ignore_cb(&mut self, transaction_id: TransactionId, cond: ConditionCode, progress: u64) {
        panic!(
            "ignoring unexpected error in transaction {:?}, condition code {:?}, progress {}",
            transaction_id, cond, progress
        );
    }
}

pub struct ExampleCfdpUser {
    entity_type: EntityType,
    completion_signal: Arc<AtomicBool>,
}

impl ExampleCfdpUser {
    pub fn new(entity_type: EntityType, completion_signal: Arc<AtomicBool>) -> Self {
        Self {
            entity_type,
            completion_signal,
        }
    }
}

impl CfdpUser for ExampleCfdpUser {
    fn transaction_indication(&mut self, id: &crate::TransactionId) {
        println!(
            "{:?} entity: Transaction indication for {:?}",
            self.entity_type, id
        );
    }

    fn eof_sent_indication(&mut self, id: &crate::TransactionId) {
        println!(
            "{:?} entity: EOF sent for transaction {:?}",
            self.entity_type, id
        );
    }

    fn transaction_finished_indication(&mut self, finished_params: &TransactionFinishedParams) {
        println!(
            "{:?} entity: Transaction finished: {:?}",
            self.entity_type, finished_params
        );
        self.completion_signal
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn metadata_recvd_indication(&mut self, md_recvd_params: &MetadataReceivedParams) {
        println!(
            "{:?} entity: Metadata received: {:?}",
            self.entity_type, md_recvd_params
        );
    }

    fn file_segment_recvd_indication(&mut self, segment_recvd_params: &FileSegmentRecvdParams) {
        println!(
            "{:?} entity: File segment {:?} received",
            self.entity_type, segment_recvd_params
        );
    }

    fn report_indication(&mut self, _id: &crate::TransactionId) {}

    fn suspended_indication(&mut self, _id: &crate::TransactionId, _condition_code: ConditionCode) {
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
        println!(
            "{:?} entity: EOF received for transaction {:?}",
            self.entity_type, id
        );
    }
}

fn end_to_end_test(with_closure: bool) {
    // Simplified event handling using atomic signals.
    let stop_signal_source = Arc::new(AtomicBool::new(false));
    let stop_signal_dest = stop_signal_source.clone();
    let stop_signal_ctrl = stop_signal_source.clone();

    let completion_signal_source = Arc::new(AtomicBool::new(false));
    let completion_signal_source_main = completion_signal_source.clone();

    let completion_signal_dest = Arc::new(AtomicBool::new(false));
    let completion_signal_dest_main = completion_signal_dest.clone();

    let srcfile = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let mut file = OpenOptions::new()
        .write(true)
        .open(&srcfile)
        .expect("opening file failed");
    file.write_all(FILE_DATA.as_bytes())
        .expect("writing file content failed");
    let destdir = tempfile::tempdir().expect("creating temp directory failed");
    let destfile = destdir.path().join("test.txt");

    let local_cfg_source = LocalEntityConfig::new(
        LOCAL_ID.into(),
        IndicationConfig::default(),
        ExampleFaultHandler::default(),
    );
    let (source_tx, source_rx) = mpsc::channel::<PduOwnedWithInfo>();
    let (dest_tx, dest_rx) = mpsc::channel::<PduOwnedWithInfo>();
    let put_request_cacher = StaticPutRequestCacher::new(2048);
    let remote_cfg_of_dest = RemoteEntityConfig::new_with_default_values(
        REMOTE_ID.into(),
        1024,
        with_closure,
        false,
        spacepackets::cfdp::TransmissionMode::Unacknowledged,
        ChecksumType::Crc32,
    );
    let seq_count_provider = SeqCountProviderSyncU16::default();
    let mut source_handler = SourceHandler::new(
        local_cfg_source,
        source_tx,
        NativeFilestore::default(),
        put_request_cacher,
        2048,
        remote_cfg_of_dest,
        seq_count_provider,
    );
    let mut cfdp_user_source = ExampleCfdpUser::new(EntityType::Sending, completion_signal_source);

    let local_cfg_dest = LocalEntityConfig::new(
        REMOTE_ID.into(),
        IndicationConfig::default(),
        ExampleFaultHandler::default(),
    );
    let remote_cfg_of_source = RemoteEntityConfig::new_with_default_values(
        LOCAL_ID.into(),
        1024,
        true,
        false,
        spacepackets::cfdp::TransmissionMode::Unacknowledged,
        ChecksumType::Crc32,
    );
    let mut dest_handler = DestinationHandler::new(
        local_cfg_dest,
        1024,
        dest_tx,
        NativeFilestore::default(),
        remote_cfg_of_source,
        StdCheckTimerCreator::default(),
    );
    let mut cfdp_user_dest = ExampleCfdpUser::new(EntityType::Receiving, completion_signal_dest);

    let put_request = PutRequestOwned::new_regular_request(
        REMOTE_ID.into(),
        srcfile.to_str().expect("invaid path string"),
        destfile.to_str().expect("invaid path string"),
        Some(TransmissionMode::Unacknowledged),
        Some(with_closure),
    )
    .expect("put request creation failed");

    let start = std::time::Instant::now();

    let jh_source = thread::spawn(move || {
        source_handler
            .put_request(&put_request)
            .expect("put request failed");
        loop {
            let mut next_delay = None;
            let mut undelayed_call_count = 0;
            let packet_info = match dest_rx.try_recv() {
                Ok(pdu_with_info) => Some(pdu_with_info),
                Err(e) => match e {
                    mpsc::TryRecvError::Empty => None,
                    mpsc::TryRecvError::Disconnected => {
                        panic!("unexpected disconnect from destination channel sender");
                    }
                },
            };
            match source_handler.state_machine(&mut cfdp_user_source, packet_info.as_ref()) {
                Ok(sent_packets) => {
                    if sent_packets == 0 {
                        next_delay = Some(Duration::from_millis(50));
                    }
                }
                Err(e) => {
                    println!("Source handler error: {}", e);
                    next_delay = Some(Duration::from_millis(50));
                }
            }
            if let Some(delay) = next_delay {
                thread::sleep(delay);
            } else {
                undelayed_call_count += 1;
            }
            if stop_signal_source.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            // Safety feature against configuration errors.
            if undelayed_call_count >= 200 {
                panic!("Source handler state machine possible in permanent loop");
            }
        }
    });

    let jh_dest = thread::spawn(move || {
        loop {
            let mut next_delay = None;
            let mut undelayed_call_count = 0;
            let packet_info = match source_rx.try_recv() {
                Ok(pdu_with_info) => Some(pdu_with_info),
                Err(e) => match e {
                    mpsc::TryRecvError::Empty => None,
                    mpsc::TryRecvError::Disconnected => {
                        panic!("unexpected disconnect from destination channel sender");
                    }
                },
            };
            match dest_handler.state_machine(&mut cfdp_user_dest, packet_info.as_ref()) {
                Ok(sent_packets) => {
                    if sent_packets == 0 {
                        next_delay = Some(Duration::from_millis(50));
                    }
                }
                Err(e) => {
                    println!("Source handler error: {}", e);
                    next_delay = Some(Duration::from_millis(50));
                }
            }
            if let Some(delay) = next_delay {
                thread::sleep(delay);
            } else {
                undelayed_call_count += 1;
            }
            if stop_signal_dest.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            // Safety feature against configuration errors.
            if undelayed_call_count >= 200 {
                panic!("Destination handler state machine possible in permanent loop");
            }
        }
    });

    loop {
        if completion_signal_source_main.load(std::sync::atomic::Ordering::Relaxed)
            && completion_signal_dest_main.load(std::sync::atomic::Ordering::Relaxed)
        {
            let file = std::fs::read_to_string(destfile).expect("reading file failed");
            assert_eq!(file, FILE_DATA);
            // Stop the threads gracefully.
            stop_signal_ctrl.store(true, std::sync::atomic::Ordering::Relaxed);
            break;
        }
        if std::time::Instant::now() - start > Duration::from_secs(2) {
            panic!("file transfer not finished in 2 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    jh_source.join().unwrap();
    jh_dest.join().unwrap();
}

#[test]
fn end_to_end_test_no_closure() {
    end_to_end_test(false);
}

#[test]
fn end_to_end_test_with_closure() {
    end_to_end_test(true);
}
