import socket
import select
import logging
import time
from threading import Thread
from typing import Tuple, Optional
from multiprocessing import Queue
from queue import Empty

from cfdppy import PacketDestination, PutRequest, get_packet_destination, CfdpState
from cfdppy.mib import (
    CheckTimerProvider,
    DefaultFaultHandlerBase,
    EntityType,
    IndicationCfg,
    RemoteEntityCfg,
)
from spacepackets.cfdp.pdu import AbstractFileDirectiveBase, PduFactory, PduHolder
from spacepackets.util import ByteFieldU16, UnsignedByteField

_LOGGER = logging.getLogger(__name__)


LOCAL_ENTITY_ID = ByteFieldU16(1)
REMOTE_ENTITY_ID = ByteFieldU16(2)
# Enable all indications for both local and remote entity.
INDICATION_CFG = IndicationCfg()

FILE_CONTENT = "Hello World!\n"
FILE_SEGMENT_SIZE = 256
MAX_PACKET_LEN = 512


def main():
    pass


if __name__ == "__main__":
    main()
