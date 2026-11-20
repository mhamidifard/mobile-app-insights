"""Stream complete capture records with their interface link type and timestamp."""

import enum
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

import dpkt

from pcap.errors import PcapParseError


class DatalinkType(enum.IntEnum):
    """Link types used by Ethernet, Android VPN and Linux cooked captures."""

    ETHERNET = 1
    RAW_IP = 101
    LINUX_SLL = 113


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise dpkt.NeedData("incomplete capture record")
    return data


def _pcap_records(stream: BinaryIO) -> Iterator[tuple[int, float, bytes]]:
    pcap = dpkt.pcap
    header_bytes = _read_exact(stream, pcap.FileHdr.__hdr_len__)
    header = pcap.FileHdr(header_bytes)
    magic = header.magic
    if magic not in pcap.MAGIC_TO_PKT_HDR:
        raise ValueError("unknown PCAP magic")
    if magic in (pcap.PMUDPCT_MAGIC, pcap.PMUDPCT_MAGIC_NANO, pcap.PACPDOM_MAGIC):
        header = pcap.LEFileHdr(header_bytes)
    linktype = _supported_linktype(header.linktype)
    record_type = pcap.MAGIC_TO_PKT_HDR[magic]
    divisor = 1e9 if magic in (pcap.TCPDUMP_MAGIC_NANO, pcap.PMUDPCT_MAGIC_NANO) else 1e6
    while record_header := stream.read(record_type.__hdr_len__):
        record = record_type(record_header)
        yield linktype, record.tv_sec + record.tv_usec / divisor, _read_exact(stream, record.caplen)


def _supported_linktype(value: int) -> DatalinkType:
    try:
        return DatalinkType(value)
    except ValueError as error:
        raise ValueError(f"unsupported capture link type {value}") from error


@dataclass(frozen=True)
class _Interface:
    linktype: DatalinkType
    snaplen: int
    ticks_per_second: int
    offset_seconds: int

    @classmethod
    def decode(cls, block: bytes, endian: str) -> "_Interface":
        ng = dpkt.pcapng
        interface = (ng.InterfaceDescriptionBlockLE if endian == "<" else ng.InterfaceDescriptionBlock)(block)
        ticks_per_second = 1_000_000
        offset_seconds = 0
        for option in interface.opts:
            if option.code == ng.PCAPNG_OPT_IF_TSRESOL:
                resolution, = struct.unpack("B", option.data)
                ticks_per_second = 2 ** (resolution & 127) if resolution & 128 else 10 ** resolution
            elif option.code == ng.PCAPNG_OPT_IF_TSOFFSET:
                offset_seconds, = struct.unpack(endian + "q", option.data)
        return cls(_supported_linktype(interface.linktype), interface.snaplen, ticks_per_second, offset_seconds)


def _pcapng_blocks(stream: BinaryIO) -> Iterator[tuple[int, str, bytes]]:
    ng = dpkt.pcapng
    endian = "<"
    while prefix := stream.read(8):
        block_type, length = struct.unpack(endian + "II", prefix)
        if block_type == ng.PCAPNG_BT_SHB:
            bom = _read_exact(stream, 4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if endian is None:
                raise ValueError("invalid section byte order")
            length = struct.unpack_from(endian + "I", prefix, 4)[0]
            prefix += bom
        if length < len(prefix) + 4 or length % 4:
            raise ValueError("invalid PCAPNG block length")
        block = prefix + _read_exact(stream, length - len(prefix))
        if struct.unpack_from(endian + "I", block, length - 4)[0] != length:
            raise ValueError("PCAPNG block length mismatch")
        yield block_type, endian, block


def _pcapng_records(stream: BinaryIO) -> Iterator[tuple[int, float | None, bytes]]:
    ng = dpkt.pcapng
    interfaces: list[_Interface] = []
    for block_type, endian, block in _pcapng_blocks(stream):
        little = endian == "<"
        if block_type == ng.PCAPNG_BT_SHB:
            section = (ng.SectionHeaderBlockLE if little else ng.SectionHeaderBlock)(block)
            if section.v_major != 1:
                raise ValueError("unsupported PCAPNG version")
            interfaces.clear()
        elif block_type == ng.PCAPNG_BT_IDB:
            interfaces.append(_Interface.decode(block, endian))
        elif block_type in (ng.PCAPNG_BT_EPB, ng.PCAPNG_BT_PB):
            if block_type == ng.PCAPNG_BT_EPB:
                packet = (ng.EnhancedPacketBlockLE if little else ng.EnhancedPacketBlock)(block)
            else:
                packet = (ng.PacketBlockLE if little else ng.PacketBlock)(block)
            if packet.iface_id >= len(interfaces) or packet.caplen > len(block) - packet.__hdr_len__:
                raise ValueError("invalid PCAPNG packet record")
            interface = interfaces[packet.iface_id]
            ticks = (packet.ts_high << 32) | packet.ts_low
            yield interface.linktype, interface.offset_seconds + ticks / interface.ticks_per_second, packet.pkt_data
        elif block_type == ng.PCAPNG_BT_SPB:
            # Simple packet blocks always refer to interface zero and carry no timestamp.
            interface = interfaces[0]
            wire_length, = struct.unpack_from(endian + "I", block, 8)
            captured = min(wire_length, interface.snaplen or wire_length)
            if len(block) != 16 + ((captured + 3) & ~3):
                raise ValueError("invalid simple packet length")
            yield interface.linktype, None, block[12:12 + captured]


def capture_records(stream: BinaryIO) -> Iterator[tuple[int, float | None, bytes]]:
    magic = stream.read(4)
    stream.seek(0)
    reader = _pcapng_records if magic == b"\x0a\x0d\x0d\x0a" else _pcap_records
    try:
        yield from reader(stream)
    except (ValueError, dpkt.UnpackError, struct.error, IndexError) as error:
        raise PcapParseError(f"cannot read {stream.name}: {error}") from error
