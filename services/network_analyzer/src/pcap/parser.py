import socket
import struct
from bisect import bisect_left
from pathlib import Path

import dpkt
from pcap.capture_reader import DatalinkType, capture_records
from pcap.errors import PcapParseError
from pcap.models import Endpoint, FlowKey, FlowRecord, ParsedCapture

from utils.logging_setup import get_logger

logger = get_logger(__name__)


_SEQ_MODULUS = 1 << 32


def _remember_range(ranges: list[tuple[int, int]], sequence: int, size: int) -> bool:
    """Merge a payload interval and report whether any of its bytes were seen before."""
    start = sequence % _SEQ_MODULUS
    if ranges:
        # Unwrap relative to the latest byte so crossing sequence zero stays contiguous.
        reference = ranges[-1][1]
        half = _SEQ_MODULUS // 2
        start = reference + (start - reference + half) % _SEQ_MODULUS - half
    end = start + size
    left = bisect_left(ranges, (start,))
    if left and ranges[left - 1][1] >= start:
        left -= 1
    right = left
    overlap = False
    while right < len(ranges) and ranges[right][0] <= end:
        old_start, old_end = ranges[right]
        overlap |= old_start < end and start < old_end
        start, end = min(start, old_start), max(end, old_end)
        right += 1
    ranges[left:right] = [(start, end)]
    return overlap


class _FlowAccumulator:
    """Mutable per-flow bookkeeping the parser folds into one FlowRecord: byte counters plus the TCP-only
    retransmission, zero-window and handshake state."""

    def __init__(self, flow_key: FlowKey) -> None:
        """Start with empty counters, no recorded handshake and no sent byte ranges."""
        self.flow_key = flow_key
        self.total_frame_bytes = 0
        self.payload_bytes = 0
        self.retransmission_count = 0
        self.zero_window_event_count = 0
        self.reset_count = 0
        self.handshake_rtt: float | None = None
        self._pending_syns: dict[tuple[Endpoint, int], float | None] = {}
        self._sent_ranges: dict[Endpoint, list[tuple[int, int]]] = {}

    def add_tcp_segment(self, timestamp: float | None, segment: dpkt.tcp.TCP, frame_length: int, source_ip: str) -> None:
        source = Endpoint(source_ip, segment.sport)
        self.total_frame_bytes += frame_length
        self.payload_bytes += len(segment.data)
        self.zero_window_event_count += segment.win == 0
        self.reset_count += bool(segment.flags & dpkt.tcp.TH_RST)
        syn = bool(segment.flags & dpkt.tcp.TH_SYN)
        if syn and self.handshake_rtt is None:
            if segment.flags & dpkt.tcp.TH_ACK:
                first = self.flow_key.first_endpoint
                peer = self.flow_key.second_endpoint if source == first else first
                started = self._pending_syns.get((peer, segment.ack))
                if started is not None and timestamp is not None and timestamp >= started:
                    self.handshake_rtt = timestamp - started
                    self._pending_syns.clear()
            else:
                key = (source, (segment.seq + 1) % _SEQ_MODULUS)
                self._pending_syns[key] = None if key in self._pending_syns else timestamp
        if segment.data:
            ranges = self._sent_ranges.setdefault(source, [])
            self.retransmission_count += _remember_range(ranges, segment.seq + syn, len(segment.data))

    def add_udp_datagram(self, datagram: dpkt.udp.UDP, frame_length: int) -> None:
        self.total_frame_bytes += frame_length
        self.payload_bytes += len(datagram.data)

    def record(self) -> FlowRecord:
        """Freeze the bookkeeping into the flow's immutable record."""
        return FlowRecord(
            flow_key=self.flow_key,
            total_frame_bytes=self.total_frame_bytes,
            payload_bytes=self.payload_bytes,
            retransmission_count=self.retransmission_count,
            zero_window_event_count=self.zero_window_event_count,
            reset_count=self.reset_count,
            handshake_rtt=self.handshake_rtt,
        )


class PcapParser:
    """Parses pcap/pcapng captures into per-flow records using dpkt (no external tools)."""

    DISSECTION_ERRORS: tuple[type[Exception], ...] = (dpkt.UnpackError, struct.error, IndexError)

    def parse(self, pcap_path: Path) -> ParsedCapture:
        """Dissect a capture into one record per TCP/UDP flow, plus the non-flow byte total.

        Flows are keyed by their canonical five-tuple, so both directions of a flow and both
        protocols on the same four-tuple are handled. Non-flow traffic (ARP, ICMP, ...) only
        counts its frame bytes. Individually malformed packets are skipped and counted; an
        unreadable file raises PcapParseError.
        """
        try:
            capture = self._parse(pcap_path)
        except OSError as error:
            raise PcapParseError(f"cannot read {pcap_path}: {error}") from error
        if capture.malformed_packet_count:
            logger.warning("%s: skipped %d malformed packet(s).", pcap_path.name, capture.malformed_packet_count)
        return capture

    def _parse(self, pcap_path: Path) -> ParsedCapture:
        flows: dict[FlowKey, _FlowAccumulator] = {}
        other_bytes = malformed = 0
        with pcap_path.open("rb") as stream:
            for linktype, timestamp, frame in capture_records(stream):
                try:
                    ip = self._decode_ip(linktype, frame)
                    if ip is None or not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        other_bytes += len(frame)
                        continue
                    segment = ip.data
                    family = socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6
                    source = socket.inet_ntop(family, ip.src)
                    destination = socket.inet_ntop(family, ip.dst)
                    protocol = "TCP" if isinstance(segment, dpkt.tcp.TCP) else "UDP"
                    key = FlowKey.from_packet(protocol, source, segment.sport, destination, segment.dport)
                    if key not in flows:
                        flows[key] = _FlowAccumulator(key)
                    if isinstance(segment, dpkt.tcp.TCP):
                        flows[key].add_tcp_segment(timestamp, segment, len(frame), source)
                    else:
                        flows[key].add_udp_datagram(segment, len(frame))
                except self.DISSECTION_ERRORS:
                    malformed += 1
        return ParsedCapture(tuple(flow.record() for flow in flows.values()), other_bytes, malformed)

    @staticmethod
    def _decode_ip(linktype: int, frame: bytes) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
        if linktype == DatalinkType.RAW_IP:
            version = frame[0] >> 4
            if version not in (4, 6):
                raise dpkt.UnpackError("invalid raw IP version")
            ip = dpkt.ip.IP(frame) if version == 4 else dpkt.ip6.IP6(frame)
        else:
            if linktype == DatalinkType.ETHERNET:
                link = dpkt.ethernet.Ethernet(frame)
                ethertype = link.type
            else:
                link = dpkt.sll.SLL(frame)
                ethertype = link.ethtype
            ip = link.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                if ethertype in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
                    raise dpkt.UnpackError("malformed IP header")
                return None
        # dpkt leaves undecodable transport headers and noninitial fragments as bytes.
        if isinstance(ip, dpkt.ip.IP):
            if ip.offset:
                return None
        else:
            fragment = ip.extension_hdrs.get(dpkt.ip.IP_PROTO_FRAGMENT)
            if fragment is not None and fragment.frag_off:
                return None
        if ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP) and isinstance(ip.data, bytes):
            raise dpkt.UnpackError("malformed transport header")
        return ip
