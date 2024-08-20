#!/usr/bin/env python3
from datetime import timedelta
from pathlib import Path
import os
import ipaddress
import tempfile
import socket
import select
import threading
import argparse
import logging
import time
import copy
from threading import Thread, Event
from typing import Any, Dict, List, Tuple, Optional
from multiprocessing import Queue
from queue import Empty

from cfdppy.handler import DestHandler, RemoteEntityCfgTable, SourceHandler
from cfdppy.exceptions import InvalidDestinationId, SourceFileDoesNotExist
from cfdppy import (
    CfdpUserBase,
    LocalEntityCfg,
    PacketDestination,
    PutRequest,
    TransactionId,
    get_packet_destination,
    CfdpState,
)
from cfdppy.mib import (
    CheckTimerProvider,
    DefaultFaultHandlerBase,
    EntityType,
    IndicationCfg,
    RemoteEntityCfg,
)
from cfdppy.user import (
    FileSegmentRecvdParams,
    MetadataRecvParams,
    TransactionFinishedParams,
    TransactionParams,
)
from spacepackets.cfdp import ChecksumType, ConditionCode, TransmissionMode
from spacepackets.cfdp.pdu import AbstractFileDirectiveBase, PduFactory, PduHolder
from spacepackets.cfdp.tlv import (
    MessageToUserTlv,
    OriginatingTransactionId,
    ProxyMessageType,
    ProxyPutResponse,
    ReservedCfdpMessage,
)
from spacepackets.cfdp.tlv.msg_to_user import ProxyPutResponseParams
from spacepackets.countdown import Countdown
from spacepackets.seqcount import SeqCountProvider
from spacepackets.util import ByteFieldU16, UnsignedByteField


PYTHON_ENTITY_ID = ByteFieldU16(1)
RUST_ENTITY_ID = ByteFieldU16(2)
# Enable all indications for both local and remote entity.
INDICATION_CFG = IndicationCfg()

BASE_STR_SRC = "PY SRC"
BASE_STR_DEST = "PY DEST"

FILE_CONTENT = "Hello World!\n"
FILE_SEGMENT_SIZE = 256
MAX_PACKET_LEN = 512

# This queue is used to send put requests.
PUT_REQ_QUEUE = Queue()
# All telecommands which should go to the source handler should be put into this queue by
# the UDP server.
SOURCE_ENTITY_QUEUE = Queue()
# All telecommands which should go to the destination handler should be put into this queue by
# the UDP server.
DEST_ENTITY_QUEUE = Queue()
# All telemetry which should be sent to the remote entity is put into this queue and will then
# be sent by the UDP server.
TM_QUEUE = Queue()

REMOTE_CFG_OF_PY_ENTITY = RemoteEntityCfg(
    entity_id=PYTHON_ENTITY_ID,
    max_packet_len=MAX_PACKET_LEN,
    max_file_segment_len=FILE_SEGMENT_SIZE,
    closure_requested=True,
    crc_on_transmission=False,
    default_transmission_mode=TransmissionMode.ACKNOWLEDGED,
    crc_type=ChecksumType.CRC_32,
)

REMOTE_CFG_OF_REMOTE_ENTITY = copy.copy(REMOTE_CFG_OF_PY_ENTITY)
REMOTE_CFG_OF_REMOTE_ENTITY.entity_id = RUST_ENTITY_ID

RUST_PORT = 5111
PY_PORT = 5222

_LOGGER = logging.getLogger(__name__)


class UdpServer(Thread):
    def __init__(
        self,
        sleep_time: float,
        addr: Tuple[str, int],
        explicit_remote_addr: Optional[Tuple[str, int]],
        tx_queue: Queue,
        source_entity_rx_queue: Queue,
        dest_entity_rx_queue: Queue,
        stop_signal: Event,
    ):
        super().__init__()
        self.sleep_time = sleep_time
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.addr = addr
        self.explicit_remote_addr = explicit_remote_addr
        self.udp_socket.bind(addr)
        self.tm_queue = tx_queue
        self.last_sender = None
        self.stop_signal = stop_signal
        self.source_entity_queue = source_entity_rx_queue
        self.dest_entity_queue = dest_entity_rx_queue

    def run(self):
        _LOGGER.info(f"Starting UDP server on {self.addr}")
        while True:
            if self.stop_signal.is_set():
                break
            self.periodic_operation()
            time.sleep(self.sleep_time)

    def periodic_operation(self):
        while True:
            next_packet = self.poll_next_udp_packet()
            if next_packet is None or next_packet.pdu is None:
                break
            # Perform PDU routing.
            packet_dest = get_packet_destination(next_packet.pdu)
            _LOGGER.debug(f"UDP server: Routing {next_packet} to {packet_dest}")
            if packet_dest == PacketDestination.DEST_HANDLER:
                self.dest_entity_queue.put(next_packet.pdu)
            elif packet_dest == PacketDestination.SOURCE_HANDLER:
                self.source_entity_queue.put(next_packet.pdu)
        self.send_packets()

    def poll_next_udp_packet(self) -> Optional[PduHolder]:
        ready = select.select([self.udp_socket], [], [], 0)
        if ready[0]:
            data, self.last_sender = self.udp_socket.recvfrom(4096)
            return PduFactory.from_raw_to_holder(data)
        return None

    def send_packets(self):
        while True:
            try:
                next_tm = self.tm_queue.get(False)
                if not isinstance(next_tm, bytes) and not isinstance(
                    next_tm, bytearray
                ):
                    _LOGGER.error(
                        f"UDP server can only sent bytearray, received {next_tm}"
                    )
                    continue
                if self.explicit_remote_addr is not None:
                    self.udp_socket.sendto(next_tm, self.explicit_remote_addr)
                elif self.last_sender is not None:
                    self.udp_socket.sendto(next_tm, self.last_sender)
                else:
                    _LOGGER.warning(
                        "UDP Server: No packet destination found, dropping TM"
                    )
            except Empty:
                break


class SourceEntityHandler(Thread):
    def __init__(
        self,
        base_str: str,
        verbose_level: int,
        source_handler: SourceHandler,
        put_req_queue: Queue,
        source_entity_queue: Queue,
        tm_queue: Queue,
        stop_signal: Event,
    ):
        super().__init__()
        self.base_str = base_str
        self.verbose_level = verbose_level
        self.source_handler = source_handler
        self.put_req_queue = put_req_queue
        self.source_entity_queue = source_entity_queue
        self.tm_queue = tm_queue
        self.stop_signal = stop_signal

    def _idle_handling(self) -> bool:
        try:
            put_req: PutRequest = self.put_req_queue.get(False)
            _LOGGER.info(f"{self.base_str}: Handling Put Request: {put_req}")
            if put_req.destination_id not in [PYTHON_ENTITY_ID, RUST_ENTITY_ID]:
                _LOGGER.warning(
                    f"can only handle put requests target towards {RUST_ENTITY_ID} or "
                    f"{PYTHON_ENTITY_ID}"
                )
            else:
                try:
                    self.source_handler.put_request(put_req)
                except SourceFileDoesNotExist as e:
                    _LOGGER.warning(
                        f"can not handle put request, source file {e.file} does not exist"
                    )
            return True
        except Empty:
            return False

    def _busy_handling(self):
        # We are getting the packets from a Queue here, they could for example also be polled
        # from a network.
        packet_received = False
        packet = None
        try:
            # We are getting the packets from a Queue here, they could for example also be polled
            # from a network.
            packet = self.source_entity_queue.get(False)
            packet_received = True
        except Empty:
            pass
        try:
            packet_sent = self._call_source_state_machine(packet)
            # If there is no work to do, put the thread to sleep.
            if not packet_received and not packet_sent:
                return False
        except SourceFileDoesNotExist:
            _LOGGER.warning("Source file does not exist")
            self.source_handler.reset()

    def _call_source_state_machine(
        self, packet: Optional[AbstractFileDirectiveBase]
    ) -> bool:
        """Returns whether a packet was sent."""

        if packet is not None:
            _LOGGER.debug(f"{self.base_str}: Inserting {packet}")
        try:
            fsm_result = self.source_handler.state_machine(packet)
        except InvalidDestinationId as e:
            _LOGGER.warning(
                f"invalid destination ID {e.found_dest_id} on packet {packet}, expected "
                f"{e.expected_dest_id}"
            )
            fsm_result = self.source_handler.state_machine(None)
        packet_sent = False
        if fsm_result.states.num_packets_ready > 0:
            while fsm_result.states.num_packets_ready > 0:
                next_pdu_wrapper = self.source_handler.get_next_packet()
                assert next_pdu_wrapper is not None
                if self.verbose_level >= 1:
                    _LOGGER.debug(
                        f"{self.base_str}: Sending packet {next_pdu_wrapper.pdu}"
                    )
                # Send all packets which need to be sent.
                self.tm_queue.put(next_pdu_wrapper.pack())
                packet_sent = True
        return packet_sent

    def run(self):
        _LOGGER.info(f"Starting {self.base_str}")
        while True:
            if self.stop_signal.is_set():
                break
            if self.source_handler.state == CfdpState.IDLE:
                if not self._idle_handling():
                    time.sleep(0.2)
                    continue
            if self.source_handler.state == CfdpState.BUSY:
                if not self._busy_handling():
                    time.sleep(0.2)


class DestEntityHandler(Thread):
    def __init__(
        self,
        base_str: str,
        verbose_level: int,
        dest_handler: DestHandler,
        dest_entity_queue: Queue,
        tm_queue: Queue,
        stop_signal: Event,
    ):
        super().__init__()
        self.base_str = base_str
        self.verbose_level = verbose_level
        self.dest_handler = dest_handler
        self.dest_entity_queue = dest_entity_queue
        self.tm_queue = tm_queue
        self.stop_signal = stop_signal

    def run(self):
        _LOGGER.info(
            f"Starting {self.base_str}. Local ID {self.dest_handler.cfg.local_entity_id}"
        )
        while True:
            packet_received = False
            packet = None
            if self.stop_signal.is_set():
                break
            try:
                packet = self.dest_entity_queue.get(False)
                packet_received = True
            except Empty:
                pass
            if packet is not None:
                _LOGGER.debug(f"{self.base_str}: Inserting {packet}")
            fsm_result = self.dest_handler.state_machine(packet)
            packet_sent = False
            if fsm_result.states.num_packets_ready > 0:
                while fsm_result.states.num_packets_ready > 0:
                    next_pdu_wrapper = self.dest_handler.get_next_packet()
                    assert next_pdu_wrapper is not None
                    if self.verbose_level >= 1:
                        _LOGGER.debug(
                            f"{self.base_str}: Sending packet {next_pdu_wrapper.pdu}"
                        )
                    self.tm_queue.put(next_pdu_wrapper.pack())
                    packet_sent = True
            # If there is no work to do, put the thread to sleep.
            if not packet_received and not packet_sent:
                time.sleep(0.5)


class CfdpFaultHandler(DefaultFaultHandlerBase):
    def __init__(self, base_str: str):
        self.base_str = base_str
        super().__init__()

    def notice_of_suspension_cb(
        self, transaction_id: TransactionId, cond: ConditionCode, progress: int
    ):
        _LOGGER.warning(
            f"{self.base_str}: Received Notice of Suspension for transaction {transaction_id!r} "
            f"with condition code {cond!r}. Progress: {progress}"
        )

    def notice_of_cancellation_cb(
        self, transaction_id: TransactionId, cond: ConditionCode, progress: int
    ):
        _LOGGER.warning(
            f"{self.base_str}: Received Notice of Cancellation for transaction {transaction_id!r} "
            f"with condition code {cond!r}. Progress: {progress}"
        )

    def abandoned_cb(
        self, transaction_id: TransactionId, cond: ConditionCode, progress: int
    ):
        _LOGGER.warning(
            f"{self.base_str}: Abandoned fault for transaction {transaction_id!r} "
            f"with condition code {cond!r}. Progress: {progress}"
        )

    def ignore_cb(
        self, transaction_id: TransactionId, cond: ConditionCode, progress: int
    ):
        _LOGGER.warning(
            f"{self.base_str}: Ignored fault for transaction {transaction_id!r} "
            f"with condition code {cond!r}. Progress: {progress}"
        )


class CfdpUser(CfdpUserBase):
    def __init__(self, base_str: str, put_req_queue: Queue):
        self.base_str = base_str
        self.put_req_queue = put_req_queue
        # This is a dictionary where the key is the current transaction ID for a transaction which
        # was triggered by a proxy request with a originating ID.
        self.active_proxy_put_reqs: Dict[TransactionId, TransactionId] = {}
        super().__init__()

    def transaction_indication(
        self,
        transaction_indication_params: TransactionParams,
    ):
        """This indication is used to report the transaction ID to the CFDP user"""
        _LOGGER.info(
            f"{self.base_str}: Transaction.indication for {transaction_indication_params.transaction_id}"
        )
        if transaction_indication_params.originating_transaction_id is not None:
            _LOGGER.info(
                f"Originating Transaction ID: {transaction_indication_params.originating_transaction_id}"
            )
            self.active_proxy_put_reqs.update(
                {
                    transaction_indication_params.transaction_id: transaction_indication_params.originating_transaction_id
                }
            )

    def eof_sent_indication(self, transaction_id: TransactionId):
        _LOGGER.info(f"{self.base_str}: EOF-Sent.indication for {transaction_id}")

    def transaction_finished_indication(self, params: TransactionFinishedParams):
        _LOGGER.info(
            f"{self.base_str}: Transaction-Finished.indication for {params.transaction_id}."
        )
        _LOGGER.info(f"Condition Code: {params.finished_params.condition_code!r}")
        _LOGGER.info(f"Delivery Code: {params.finished_params.delivery_code!r}")
        _LOGGER.info(f"File Status: {params.finished_params.file_status!r}")
        if params.transaction_id in self.active_proxy_put_reqs:
            proxy_put_response = ProxyPutResponse(
                ProxyPutResponseParams.from_finished_params(params.finished_params)
            ).to_generic_msg_to_user_tlv()
            originating_id = self.active_proxy_put_reqs.get(params.transaction_id)
            assert originating_id is not None
            put_req = PutRequest(
                destination_id=originating_id.source_id,
                source_file=None,
                dest_file=None,
                trans_mode=None,
                closure_requested=None,
                msgs_to_user=[
                    proxy_put_response,
                    OriginatingTransactionId(
                        originating_id
                    ).to_generic_msg_to_user_tlv(),
                ],
            )
            _LOGGER.info(
                f"Requesting Proxy Put Response concluding Proxy Put originating from "
                f"{originating_id}"
            )
            self.put_req_queue.put(put_req)
            self.active_proxy_put_reqs.pop(params.transaction_id)

    def metadata_recv_indication(self, params: MetadataRecvParams):
        _LOGGER.info(
            f"{self.base_str}: Metadata-Recv.indication for {params.transaction_id}."
        )
        if params.msgs_to_user is not None:
            self._handle_msgs_to_user(params.transaction_id, params.msgs_to_user)

    def _handle_msgs_to_user(
        self, transaction_id: TransactionId, msgs_to_user: List[MessageToUserTlv]
    ):
        for msg_to_user in msgs_to_user:
            if msg_to_user.is_reserved_cfdp_message():
                reserved_msg_tlv = msg_to_user.to_reserved_msg_tlv()
                assert reserved_msg_tlv is not None
                self._handle_reserved_cfdp_message(transaction_id, reserved_msg_tlv)
            else:
                _LOGGER.info(f"Received custom message to user: {msg_to_user}")

    def _handle_reserved_cfdp_message(
        self, transaction_id: TransactionId, reserved_cfdp_msg: ReservedCfdpMessage
    ):
        if reserved_cfdp_msg.is_cfdp_proxy_operation():
            self._handle_cfdp_proxy_operation(transaction_id, reserved_cfdp_msg)
        elif reserved_cfdp_msg.is_originating_transaction_id():
            _LOGGER.info(
                f"Received originating transaction ID: "
                f"{reserved_cfdp_msg.get_originating_transaction_id()}"
            )

    def _handle_cfdp_proxy_operation(
        self, transaction_id: TransactionId, reserved_cfdp_msg: ReservedCfdpMessage
    ):
        if (
            reserved_cfdp_msg.get_cfdp_proxy_message_type()
            == ProxyMessageType.PUT_REQUEST
        ):
            put_req_params = reserved_cfdp_msg.get_proxy_put_request_params()
            _LOGGER.info(f"Received Proxy Put Request: {put_req_params}")
            assert put_req_params is not None
            put_req = PutRequest(
                destination_id=put_req_params.dest_entity_id,
                source_file=Path(put_req_params.source_file_as_path),
                dest_file=Path(put_req_params.dest_file_as_path),
                trans_mode=None,
                closure_requested=None,
                msgs_to_user=[
                    OriginatingTransactionId(
                        transaction_id
                    ).to_generic_msg_to_user_tlv()
                ],
            )
            self.put_req_queue.put(put_req)
        elif (
            reserved_cfdp_msg.get_cfdp_proxy_message_type()
            == ProxyMessageType.PUT_RESPONSE
        ):
            put_response_params = reserved_cfdp_msg.get_proxy_put_response_params()
            _LOGGER.info(f"Received Proxy Put Response: {put_response_params}")

    def file_segment_recv_indication(self, params: FileSegmentRecvdParams):
        _LOGGER.info(
            f"{self.base_str}: File-Segment-Recv.indication for {params.transaction_id}."
        )

    def report_indication(self, transaction_id: TransactionId, status_report: Any):
        # TODO: p.28 of the CFDP standard specifies what information the status report parameter
        #       could contain. I think it would be better to not hardcode the type of the status
        #       report here, but something like Union[any, CfdpStatusReport] with CfdpStatusReport
        #       being an implementation which supports all three information suggestions would be
        #       nice
        pass

    def suspended_indication(
        self, transaction_id: TransactionId, cond_code: ConditionCode
    ):
        _LOGGER.info(
            f"{self.base_str}: Suspended.indication for {transaction_id} | Condition Code: {cond_code}"
        )

    def resumed_indication(self, transaction_id: TransactionId, progress: int):
        _LOGGER.info(
            f"{self.base_str}: Resumed.indication for {transaction_id} | Progress: {progress} bytes"
        )

    def fault_indication(
        self, transaction_id: TransactionId, cond_code: ConditionCode, progress: int
    ):
        _LOGGER.info(
            f"{self.base_str}: Fault.indication for {transaction_id} | Condition Code: {cond_code} | "
            f"Progress: {progress} bytes"
        )

    def abandoned_indication(
        self, transaction_id: TransactionId, cond_code: ConditionCode, progress: int
    ):
        _LOGGER.info(
            f"{self.base_str}: Abandoned.indication for {transaction_id} | Condition Code: {cond_code} |"
            f" Progress: {progress} bytes"
        )

    def eof_recv_indication(self, transaction_id: TransactionId):
        _LOGGER.info(f"{self.base_str}: EOF-Recv.indication for {transaction_id}")


class CustomCheckTimerProvider(CheckTimerProvider):
    def provide_check_timer(
        self,
        local_entity_id: UnsignedByteField,
        remote_entity_id: UnsignedByteField,
        entity_type: EntityType,
    ) -> Countdown:
        return Countdown(timedelta(seconds=5.0))


def main():
    parser = argparse.ArgumentParser(
        prog="CFDP Local Entity Application",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument(
        "-f",
        help="Perform a file-copy operation",
        action="store_true",
        dest="file_copy",
    )
    parser.add_argument(
        "-m",
        "--mode",
        dest="transmission_mode",
        help=(
            f"Specify the transfer type{os.linesep}"
            f' - "0" or "ack" for unacknowledged (Class 0) transfers{os.linesep}'
            f' - "1" or "nak" for acknowledged (Class 1) transfers. Default value'
        ),
        default="nak",
    )
    # Optional Boolean argument where you can specify True/False
    parser.add_argument(
        "-c",
        type=bool,
        nargs="?",
        const=True,
        default=None,
        dest="closure_requested",
        help="Request transaction closure for the unacknowledged mode",
    )
    args = parser.parse_args()
    stop_signal = threading.Event()

    logging_level = logging.INFO
    if args.verbose >= 1:
        logging_level = logging.DEBUG

    logging.basicConfig(level=logging_level)

    remote_cfg_table = RemoteEntityCfgTable()
    remote_cfg_table.add_config(REMOTE_CFG_OF_REMOTE_ENTITY)

    src_fault_handler = CfdpFaultHandler(BASE_STR_SRC)
    # 16 bit sequence count for transactions.
    src_seq_count_provider = SeqCountProvider(16)
    src_user = CfdpUser(BASE_STR_SRC, PUT_REQ_QUEUE)
    check_timer_provider = CustomCheckTimerProvider()
    source_handler = SourceHandler(
        cfg=LocalEntityCfg(PYTHON_ENTITY_ID, INDICATION_CFG, src_fault_handler),
        seq_num_provider=src_seq_count_provider,
        remote_cfg_table=remote_cfg_table,
        user=src_user,
        check_timer_provider=check_timer_provider,
    )
    source_entity_task = SourceEntityHandler(
        BASE_STR_SRC,
        logging_level,
        source_handler,
        PUT_REQ_QUEUE,
        SOURCE_ENTITY_QUEUE,
        TM_QUEUE,
        stop_signal,
    )

    # Enable all indications.
    dest_fault_handler = CfdpFaultHandler(BASE_STR_DEST)
    dest_user = CfdpUser(BASE_STR_DEST, PUT_REQ_QUEUE)
    dest_handler = DestHandler(
        cfg=LocalEntityCfg(PYTHON_ENTITY_ID, INDICATION_CFG, dest_fault_handler),
        user=dest_user,
        remote_cfg_table=remote_cfg_table,
        check_timer_provider=check_timer_provider,
    )
    dest_entity_task = DestEntityHandler(
        BASE_STR_DEST,
        logging_level,
        dest_handler,
        DEST_ENTITY_QUEUE,
        TM_QUEUE,
        stop_signal,
    )

    # Address Any to accept CFDP packets from other address than localhost.
    local_addr = ipaddress.ip_address("0.0.0.0")
    # Localhost as default.
    remote_addr = ipaddress.ip_address("127.0.0.1")
    udp_server = UdpServer(
        sleep_time=0.1,
        addr=(str(local_addr), PY_PORT),
        explicit_remote_addr=(str(remote_addr), RUST_PORT),
        tx_queue=TM_QUEUE,
        source_entity_rx_queue=SOURCE_ENTITY_QUEUE,
        dest_entity_rx_queue=DEST_ENTITY_QUEUE,
        stop_signal=stop_signal,
    )

    # Prepare a put request / file copy operation if the user specifies it.
    if args.file_copy:
        _LOGGER.info("Performing file copy operation")
        transmission_mode = None
        if args.transmission_mode == "ack":
            transmission_mode = TransmissionMode.ACKNOWLEDGED
        elif args.transmission_mode == "nak":
            transmission_mode = TransmissionMode.UNACKNOWLEDGED
        with tempfile.NamedTemporaryFile(delete=False) as srcfile:
            srcfile.write(FILE_CONTENT.encode())
            srcfile_path = srcfile.name
        tempdir = tempfile.TemporaryDirectory()
        put_req = PutRequest(
            destination_id=RUST_ENTITY_ID,
            source_file=Path(srcfile_path),
            dest_file=Path(tempdir.name).joinpath("test.txt"),
            closure_requested=args.closure_requested,
            trans_mode=transmission_mode,
        )
        PUT_REQ_QUEUE.put(put_req)

    source_entity_task.start()
    dest_entity_task.start()
    udp_server.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_signal.set()

    source_entity_task.join()
    dest_entity_task.join()
    udp_server.join()


if __name__ == "__main__":
    main()
