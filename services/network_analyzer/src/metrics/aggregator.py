from collections import Counter
from statistics import fmean

from configs import WELL_KNOWN_PORTS
from metrics.models import PcapMetrics
from pcap.models import FlowRecord, ParsedCapture


class PcapMetricsAggregator:
    """Reduces a parsed capture's flows into the aggregate metrics stored in the network_metrics table."""

    def aggregate(self, capture: ParsedCapture) -> PcapMetrics:
        tcp_flows = [flow for flow in capture.flows if flow.flow_key.protocol == "TCP"]
        rtts = [flow.handshake_rtt for flow in tcp_flows if flow.handshake_rtt is not None]
        transferred = capture.other_frame_bytes + sum(flow.total_frame_bytes for flow in capture.flows)
        payload = sum(flow.payload_bytes for flow in capture.flows)
        return PcapMetrics(
            handshake_rtt_avg=fmean(rtts) if rtts else None,
            retransmission_count=sum(flow.retransmission_count for flow in tcp_flows),
            zero_window_event_count=sum(flow.zero_window_event_count for flow in tcp_flows),
            tcp_reset_drops=sum(flow.reset_count for flow in tcp_flows),
            total_transferred_bytes=transferred,
            total_payload_bytes=payload,
            overhead_ratio=(transferred - payload) / transferred if transferred > 0 else None,
            dominant_server_port=_dominant_server_port(capture.flows),
        )


def _dominant_server_port(flows: tuple[FlowRecord, ...]) -> int | None:
    """Attribute a flow's frame bytes only when its endpoints identify one known port."""
    bytes_by_port: Counter[int] = Counter()
    for flow in flows:
        key = flow.flow_key
        candidates = {key.first_endpoint.port, key.second_endpoint.port} & WELL_KNOWN_PORTS
        if len(candidates) == 1 and flow.total_frame_bytes > 0:
            port, = candidates
            bytes_by_port[port] += flow.total_frame_bytes
    return min(bytes_by_port, key=lambda port: (-bytes_by_port[port], port), default=None)


