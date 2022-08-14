"""
Generates packet or reconstructed stream output with ANSI color codes.

Based on output module originally written by amm
"""

import logging
import struct
from os import path
from typing import List, cast

import dshell.core
import dshell.util
from dshell.output.output import Output

logger = logging.getLogger(__name__)

class ExportOutput(Output):
    _DESCRIPTION = "Reconstructed output"

    _DEFAULT_DELIM = "\n\n"

    PCAP_FILE = "pcap_%d.pcap"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dir = kwargs.get('outdir')
        self.link_layer_type = None
        self.data = []

    def write(self, *args, **kwargs):
        rawData = []
        direction = []
        packets: List[dshell.core.Packet] = []
        for arg in args:
            if type(arg) == dshell.core.Blob:
                arg = cast(dshell.core.Blob, arg)
                if arg.data:
                    rawData.append(arg.data)
                    direction.append(arg.direction)
                packets = packets + arg.packets
            elif type(arg) == dshell.core.Connection:
                arg = cast(dshell.core.Connection, arg)
                for blob in arg.blobs:
                    if blob.data:
                        rawData.append(blob.data)
                        direction.append(blob.direction)
                packets = packets + arg.packets
            elif type(arg) == dshell.core.Packet:
                rawData.append(arg.pkt.body_bytes)
                direction.append(kwargs.get('direction', 'unknown'))
                packets.append(arg)
            elif type(arg) == tuple:
                rawData.append(arg[0])
                direction.append(arg[1])
            else:
                rawData.append(arg)
                direction.append(kwargs.get('direction', 'unknown'))


        if not self.dir:
            raise Exception("dir must be specified")
        data = {
            **kwargs,
            "packets": [''.join(map(chr,i)) for i in rawData],
            "direction": direction,
            "file": path.join(self.dir, self.PCAP_FILE % len(self.data))
        }
        logger.info(f"Writing Packet {data['file']}")
        with open(data["file"], 'wb') as f:
            link_layer_type = self.link_layer_type or 1
            f.write(
                struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, len(packets), link_layer_type))
            for packet in packets:
                ts = packet.ts
                rawpkt = packet.rawpkt
                pktlen = packet.pktlen
                f.write(struct.pack('II', int(ts),
                        int((ts - int(ts)) * 1000000)))
                f.write(struct.pack('II', len(rawpkt), pktlen))
                f.write(rawpkt)
        self.data.append(data)


obj = ExportOutput
