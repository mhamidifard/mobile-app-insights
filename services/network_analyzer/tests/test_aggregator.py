import pytest
from metrics.aggregator import PcapMetricsAggregator
from metrics.models import PcapMetrics
from pcap.analyzer import PcapAnalyzer
from pcap.models import FlowKey, FlowRecord, ParsedCapture

from tests.builders import handshake_packets, write_pcap


def flow_key(protocol, source_port, destination_port):
    return FlowKey.from_packet(protocol, "192.0.2.1", source_port, "192.0.2.2", destination_port)


def test_aggregates_mixed_flows_and_nonflow_bytes():
    flows = (
        FlowRecord(flow_key("TCP", 50000, 443), 600, payload_bytes=450, handshake_rtt=0.0,
                   retransmission_count=2, zero_window_event_count=1),
        FlowRecord(flow_key("TCP", 50001, 53), 200, payload_bytes=100, handshake_rtt=0.1,
                   reset_count=1, retransmission_count=3),
        FlowRecord(flow_key("TCP", 50002, 53), 60, zero_window_event_count=2, reset_count=2),
        FlowRecord(flow_key("UDP", 50003, 53), 200, payload_bytes=120),
    )
    metrics = PcapMetricsAggregator().aggregate(ParsedCapture(flows, other_frame_bytes=40, malformed_packet_count=3))

    assert metrics == PcapMetrics(
        handshake_rtt_avg=0.05, retransmission_count=5, zero_window_event_count=3, tcp_reset_drops=3,
        total_transferred_bytes=1100, total_payload_bytes=670, overhead_ratio=430 / 1100, dominant_server_port=443,
    )


@pytest.mark.parametrize("other_bytes, ratio", [(0, None), (80, 1.0)])
def test_capture_without_flows(other_bytes, ratio):
    metrics = PcapMetricsAggregator().aggregate(ParsedCapture((), other_bytes, 0))
    assert metrics == PcapMetrics(
        handshake_rtt_avg=None, retransmission_count=0, zero_window_event_count=0, tcp_reset_drops=0,
        total_transferred_bytes=other_bytes, total_payload_bytes=0, overhead_ratio=ratio, dominant_server_port=None,
    )


@pytest.mark.parametrize("traffic, expected_port", [
    ([(443, 50000, 100), (50001, 53, 60), (50002, 53, 41)], 53),
    ([(50000, 443, 100), (50001, 53, 100)], 53),
    ([(80, 443, 900), (50000, 50001, 800), (53, 53, 50)], 53),
    ([(80, 443, 900), (50000, 50001, 800), (53, 50002, 0)], None),
])
def test_dominant_port_by_attributable_bytes(traffic, expected_port):
    flows = tuple(FlowRecord(flow_key("UDP", source, dest), size) for source, dest, size in traffic)
    metrics = PcapMetricsAggregator().aggregate(ParsedCapture(flows, 0, 0))
    assert metrics.dominant_server_port == expected_port
    assert metrics.total_transferred_bytes == sum(size for _, _, size in traffic)


def test_analyzes_ethernet_handshake_end_to_end(tmp_path):
    path = tmp_path / "handshake.pcap"
    write_pcap(path, handshake_packets())

    metrics = PcapAnalyzer().analyze(path)
    assert metrics.handshake_rtt_avg == pytest.approx(0.05)
    assert metrics.total_transferred_bytes == 262
    assert metrics.total_payload_bytes == 100
    assert metrics.overhead_ratio == pytest.approx(162 / 262)
    assert metrics.retransmission_count == metrics.zero_window_event_count == metrics.tcp_reset_drops == 0
    assert metrics.dominant_server_port == 443
