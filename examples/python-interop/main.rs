use std::{
    fmt::Debug,
    fs::OpenOptions,
    io::{self, ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU16},
        mpsc,
    },
    thread,
    time::Duration,
};

use cfdp::{
    EntityType, FaultInfo, IndicationConfig, LocalEntityConfig, PduOwnedWithInfo, PduProvider,
    RemoteEntityConfig, StdTimerCreator, TransactionId, UserFaultHook,
    dest::DestinationHandler,
    filestore::NativeFilestore,
    lost_segments::LostSegmentsList,
    request::PutRequestOwned,
    source::SourceHandler,
    user::{CfdpUser, FileSegmentRecvdParams, MetadataReceivedParams, TransactionFinishedParams},
};
use clap::Parser;
use log::{debug, info, warn};
use spacepackets::{
    cfdp::{
        ChecksumType, ConditionCode, TransmissionMode,
        pdu::{PduError, file_data::FileDataPdu, metadata::MetadataPduReader},
    },
    util::{UnsignedByteFieldU16, UnsignedEnum},
};

static KILL_APP: AtomicBool = AtomicBool::new(false);

const PYTHON_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(1);
const RUST_ID: UnsignedByteFieldU16 = UnsignedByteFieldU16::new(2);

const RUST_PORT: u16 = 5111;
const PY_PORT: u16 = 5222;

const LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;

const FILE_DATA: &str = "Hello World!";

#[derive(Debug, Copy, Clone, clap::ValueEnum)]
pub enum TransmissionModeCli {
    Nak,
    Ack,
}

#[derive(clap::Parser)]
#[command(about = "Arguments for executing a file copy operation")]
pub struct Cli {
    #[arg(short, help = "Perform a file copy operation")]
    file_copy: bool,
    #[arg(short, default_value = "nak")]
    mode: Option<TransmissionModeCli>,
    #[arg(short)]
    closure_requested: Option<bool>,
}

#[derive(Default)]
pub struct ExampleFaultHandler {}

impl UserFaultHook for ExampleFaultHandler {
    fn notice_of_suspension_cb(&mut self, fault_info: FaultInfo) {
        panic!("unexpected suspension, {:?}", fault_info);
    }

    fn notice_of_cancellation_cb(&mut self, fault_info: FaultInfo) {
        panic!("unexpected cancellation, {:?}", fault_info);
    }

    fn abandoned_cb(&mut self, fault_info: FaultInfo) {
        panic!("unexpected abandonment, {:?}", fault_info);
    }

    fn ignore_cb(&mut self, fault_info: FaultInfo) {
        panic!("unexpected ignore, {:?}", fault_info);
    }
}

pub struct ExampleCfdpUser {
    entity_type: EntityType,
}

impl ExampleCfdpUser {
    pub fn new(entity_type: EntityType) -> Self {
        Self { entity_type }
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

pub struct UdpServer {
    pub socket: UdpSocket,
    recv_buf: Vec<u8>,
    remote_addr: SocketAddr,
    source_tc_tx: mpsc::Sender<PduOwnedWithInfo>,
    dest_tc_tx: mpsc::Sender<PduOwnedWithInfo>,
    source_tm_rx: mpsc::Receiver<PduOwnedWithInfo>,
    dest_tm_rx: mpsc::Receiver<PduOwnedWithInfo>,
}

#[derive(Debug, thiserror::Error)]
pub enum UdpServerError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("pdu error: {0}")]
    Pdu(#[from] PduError),
    #[error("send error")]
    Send,
}

impl UdpServer {
    pub fn new<A: ToSocketAddrs>(
        addr: A,
        remote_addr: SocketAddr,
        max_recv_size: usize,
        source_tc_tx: mpsc::Sender<PduOwnedWithInfo>,
        dest_tc_tx: mpsc::Sender<PduOwnedWithInfo>,
        source_tm_rx: mpsc::Receiver<PduOwnedWithInfo>,
        dest_tm_rx: mpsc::Receiver<PduOwnedWithInfo>,
    ) -> Result<Self, io::Error> {
        let server = Self {
            socket: UdpSocket::bind(addr)?,
            recv_buf: vec![0; max_recv_size],
            source_tc_tx,
            dest_tc_tx,
            remote_addr,
            source_tm_rx,
            dest_tm_rx,
        };
        server.socket.set_nonblocking(true)?;
        Ok(server)
    }

    pub fn try_recv_tc(
        &mut self,
    ) -> Result<Option<(PduOwnedWithInfo, SocketAddr)>, UdpServerError> {
        let res = match self.socket.recv_from(&mut self.recv_buf) {
            Ok(res) => res,
            Err(e) => {
                return if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                    Ok(None)
                } else {
                    Err(e.into())
                };
            }
        };
        let (_, from) = res;
        self.remote_addr = from;
        let pdu_owned = PduOwnedWithInfo::new_from_raw_packet(&self.recv_buf)?;
        match pdu_owned.packet_target()? {
            cfdp::PacketTarget::SourceEntity => {
                self.source_tc_tx
                    .send(pdu_owned.clone())
                    .map_err(|_| UdpServerError::Send)?;
            }
            cfdp::PacketTarget::DestEntity => {
                self.dest_tc_tx
                    .send(pdu_owned.clone())
                    .map_err(|_| UdpServerError::Send)?;
            }
        }
        Ok(Some((pdu_owned, from)))
    }

    pub fn recv_and_send_telemetry(&mut self) {
        let tm_handler = |receiver: &mpsc::Receiver<PduOwnedWithInfo>| {
            while let Ok(tm) = receiver.try_recv() {
                debug!("Sending PDU: {:?}", tm);
                pdu_printout(&tm);
                let result = self.socket.send_to(tm.raw_pdu(), self.remote_addr());
                if let Err(e) = result {
                    warn!("Sending TM with UDP socket failed: {e}")
                }
            }
        };
        tm_handler(&self.source_tm_rx);
        tm_handler(&self.dest_tm_rx);
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

fn pdu_printout(pdu: &PduOwnedWithInfo) {
    match pdu.pdu_type() {
        spacepackets::cfdp::PduType::FileDirective => match pdu.file_directive_type().unwrap() {
            spacepackets::cfdp::pdu::FileDirectiveType::EofPdu => (),
            spacepackets::cfdp::pdu::FileDirectiveType::FinishedPdu => (),
            spacepackets::cfdp::pdu::FileDirectiveType::AckPdu => (),
            spacepackets::cfdp::pdu::FileDirectiveType::MetadataPdu => {
                let meta_pdu =
                    MetadataPduReader::new(pdu.raw_pdu()).expect("creating metadata pdu failed");
                debug!("Metadata PDU: {:?}", meta_pdu)
            }
            spacepackets::cfdp::pdu::FileDirectiveType::NakPdu => (),
            spacepackets::cfdp::pdu::FileDirectiveType::PromptPdu => (),
            spacepackets::cfdp::pdu::FileDirectiveType::KeepAlivePdu => (),
        },
        spacepackets::cfdp::PduType::FileData => {
            let fd_pdu =
                FileDataPdu::from_bytes(pdu.raw_pdu()).expect("creating file data pdu failed");
            debug!("File data PDU: {:?}", fd_pdu);
        }
    }
}

fn main() {
    let cli_args = Cli::parse();
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                std::thread::current().name().expect("thread is not named"),
                record.level(),
                message
            ))
        })
        .level(LOG_LEVEL)
        .chain(std::io::stdout())
        .apply()
        .unwrap();

    let srcfile = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let mut file = OpenOptions::new()
        .write(true)
        .open(&srcfile)
        .expect("opening file failed");
    info!("created test source file {:?}", srcfile);
    file.write_all(FILE_DATA.as_bytes())
        .expect("writing file content failed");
    let destdir = tempfile::tempdir().expect("creating temp directory failed");
    let destfile = destdir.path().join("test.txt");

    let local_cfg_source = LocalEntityConfig::new(
        RUST_ID.into(),
        IndicationConfig::default(),
        ExampleFaultHandler::default(),
    );
    let (source_tm_tx, source_tm_rx) = mpsc::channel::<PduOwnedWithInfo>();
    let (dest_tm_tx, dest_tm_rx) = mpsc::channel::<PduOwnedWithInfo>();
    let remote_cfg_python = RemoteEntityConfig::new_with_default_values(
        PYTHON_ID.into(),
        1024,
        true,
        false,
        spacepackets::cfdp::TransmissionMode::Unacknowledged,
        ChecksumType::Crc32C,
    );
    let seq_count_provider = AtomicU16::default();
    let mut source_handler = SourceHandler::new(
        local_cfg_source,
        source_tm_tx,
        NativeFilestore::default(),
        remote_cfg_python,
        StdTimerCreator::default(),
        seq_count_provider,
    );
    let mut cfdp_user_source = ExampleCfdpUser::new(EntityType::Sending);

    let local_cfg_dest = LocalEntityConfig::new(
        RUST_ID.into(),
        IndicationConfig::default(),
        ExampleFaultHandler::default(),
    );
    let mut dest_handler = DestinationHandler::new(
        local_cfg_dest,
        dest_tm_tx,
        NativeFilestore::default(),
        remote_cfg_python,
        StdTimerCreator::default(),
        LostSegmentsList::default(),
    );
    let mut cfdp_user_dest = ExampleCfdpUser::new(EntityType::Receiving);

    let put_request = if cli_args.file_copy {
        Some(
            PutRequestOwned::new_regular_request(
                PYTHON_ID.into(),
                srcfile.to_str().expect("invaid path string"),
                destfile.to_str().expect("invaid path string"),
                cli_args.mode.map(|m| match m {
                    TransmissionModeCli::Ack => TransmissionMode::Acknowledged,
                    TransmissionModeCli::Nak => TransmissionMode::Unacknowledged,
                }),
                cli_args.closure_requested,
            )
            .expect("put request creation failed"),
        )
    } else {
        None
    };

    let (source_tc_tx, source_tc_rx) = mpsc::channel();
    let (dest_tc_tx, dest_tc_rx) = mpsc::channel();

    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), RUST_PORT);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PY_PORT);
    let mut udp_server = UdpServer::new(
        local_addr,
        remote_addr,
        2048,
        source_tc_tx,
        dest_tc_tx,
        source_tm_rx,
        dest_tm_rx,
    )
    .expect("creating UDP server failed");

    let jh_source = thread::Builder::new()
        .name("cfdp src entity".to_string())
        .spawn(move || {
            info!("Starting RUST SRC");
            if let Some(put_request) = put_request {
                info!("RUST SRC: Performing put request: {:?}", put_request);
                source_handler
                    .put_request(&put_request)
                    .expect("put request failed");
            }
            loop {
                if KILL_APP.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let mut next_delay = None;
                let mut undelayed_call_count = 0;
                let packet_info = match source_tc_rx.try_recv() {
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
                        warn!("cfdp src entity error: {}", e);
                        next_delay = Some(Duration::from_millis(50));
                    }
                }
                if let Some(delay) = next_delay {
                    thread::sleep(delay);
                } else {
                    undelayed_call_count += 1;
                }
                // Safety feature against configuration errors.
                if undelayed_call_count >= 200 {
                    panic!("Source handler state machine possible in permanent loop");
                }
            }
        })
        .unwrap();

    let jh_dest = thread::Builder::new()
        .name("cfdp dest entity".to_string())
        .spawn(move || {
            info!("Starting RUST DEST. Local ID {}", RUST_ID.value());
            loop {
                let mut next_delay = None;
                let mut undelayed_call_count = 0;
                if KILL_APP.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let packet_info = match dest_tc_rx.try_recv() {
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
                        println!("Dest handler error: {}", e);
                        // TODO: I'd prefer a proper cancel request if a transfer is active..
                        dest_handler.reset();
                        next_delay = Some(Duration::from_millis(50));
                    }
                }
                if let Some(delay) = next_delay {
                    thread::sleep(delay);
                } else {
                    undelayed_call_count += 1;
                }
                // Safety feature against configuration errors.
                if undelayed_call_count >= 200 {
                    panic!("Destination handler state machine possible in permanent loop");
                }
            }
        })
        .unwrap();

    let jh_udp_server = thread::Builder::new()
        .name("cfdp udp server".to_string())
        .spawn(move || {
            info!("Starting UDP server on {}", remote_addr);
            loop {
                loop {
                    if KILL_APP.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match udp_server.try_recv_tc() {
                        Ok(result) => match result {
                            Some((pdu, _addr)) => {
                                debug!("Received PDU on UDP server: {:?}", pdu);
                                pdu_printout(&pdu);
                            }
                            None => break,
                        },
                        Err(e) => {
                            warn!("UDP server error: {}", e);
                            break;
                        }
                    }
                }
                udp_server.recv_and_send_telemetry();
                thread::sleep(Duration::from_millis(50));
            }
        })
        .unwrap();

    jh_source.join().unwrap();
    jh_dest.join().unwrap();
    jh_udp_server.join().unwrap();
}
