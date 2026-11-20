import socket

import dpkt
import pytest
from pcap.errors import PcapParseError
from pcap.parser import PcapParser

from tests.builders import (
    CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, arp_packet, handshake_packets,
    malformed_packet_bytes, pcapng_block, pcapng_enhanced_packet_block, pcapng_interface_description_block,
    pcapng_section_header_block, tcp_packet, truncated_record_pcap_bytes, udp_packet, write_pcap,
)


@pytest.mark.parametrize("raw_ip, expected_bytes", [(False, 262), (True, 220)])
def test_bidirectional_handshake_in_both_capture_formats(tmp_path, raw_ip, expected_bytes):
    path = tmp_path / "capture"
    packets = handshake_packets()
    if raw_ip:
        path.write_bytes(
            pcapng_section_header_block() + pcapng_interface_description_block(101)
            + b"".join(pcapng_enhanced_packet_block(ts, frame[14:]) for ts, frame in packets)
        )
    else:
        write_pcap(path, packets)

    capture = PcapParser().parse(path)
    flow, = capture.flows
    assert flow.handshake_rtt == pytest.approx(0.05)
    assert flow.total_frame_bytes == expected_bytes
    assert flow.payload_bytes == 100
    assert flow.retransmission_count == flow.reset_count == flow.zero_window_event_count == 0
    assert capture.other_frame_bytes == capture.malformed_packet_count == 0


def test_tcp_counters_distinguish_direction_and_payload_overlap(tmp_path):
    client = (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
    server = (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
    frames = [
        tcp_packet(*client, sequence_number=100, payload=b"abcdefghij"),
        tcp_packet(*server, sequence_number=100, payload=b"other"),
        tcp_packet(*client, sequence_number=90, payload=b"earlier"),
        tcp_packet(*client, sequence_number=105, payload=b"overlapping"),
        tcp_packet(*client, sequence_number=101, payload=b"repeat"),
        tcp_packet(*client, sequence_number=105, flags=dpkt.tcp.TH_ACK, window_size=0),
        tcp_packet(*server, flags=dpkt.tcp.TH_RST, window_size=0),
        udp_packet(*client, payload=b"one"),
        udp_packet(*server, payload=b"two"),
    ]
    path = tmp_path / "mixed.pcap"
    write_pcap(path, list(enumerate(frames)))
    capture = PcapParser().parse(path)
    tcp, udp = capture.flows
    assert (tcp.flow_key.protocol, udp.flow_key.protocol) == ("TCP", "UDP")
    assert tcp.retransmission_count == 2
    assert tcp.zero_window_event_count == 2
    assert tcp.reset_count == 1
    assert tcp.handshake_rtt is None
    assert tcp.payload_bytes == 39
    assert udp.payload_bytes == 6
    assert tcp.total_frame_bytes == sum(map(len, frames[:7]))
    assert udp.total_frame_bytes == sum(map(len, frames[7:]))


@pytest.mark.parametrize("response", ["repeated_syn", "wrong_ack", "same_direction", "missing"])
def test_requires_an_unambiguous_matching_syn_ack(tmp_path, response):
    syn, syn_ack, _ = handshake_packets()
    packets = [syn]
    if response == "repeated_syn":
        packets += [(1.02, syn[1]), syn_ack]
    elif response in ("wrong_ack", "same_direction"):
        endpoints = (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
        if response == "same_direction":
            endpoints = (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
        packets.append((1.05, tcp_packet(
            *endpoints, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            acknowledgment_number=102 if response == "wrong_ack" else 101,
        )))
    path = tmp_path / "handshake.pcap"
    write_pcap(path, packets)
    flow, = PcapParser().parse(path).flows
    assert flow.handshake_rtt is None


def test_linux_cooked_ipv6_udp(tmp_path):
    segment = dpkt.udp.UDP(sport=2000, dport=3000, ulen=11, data=b"udp")
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                      dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
                      nxt=17, plen=len(segment), data=segment)
    frame = bytes(dpkt.sll.SLL(ethtype=dpkt.ethernet.ETH_TYPE_IP6, data=ip))
    path = tmp_path / "ipv6.pcap"
    write_pcap(path, [(1, frame)], linktype=113)
    flow, = PcapParser().parse(path).flows
    assert flow.payload_bytes == 3
    assert flow.total_frame_bytes == len(frame)
    assert flow.flow_key.first_endpoint.ip == "2001:db8::1"


def test_untimed_simple_packet_counts_bytes_without_inventing_rtt(tmp_path):
    path = tmp_path / "untimed.pcapng"
    syn, syn_ack, _ = handshake_packets()
    packet = syn[1][14:]
    body = len(packet).to_bytes(4, "little") + packet
    path.write_bytes(
        pcapng_section_header_block() + pcapng_interface_description_block(101)
        + pcapng_block(3, body) + pcapng_enhanced_packet_block(syn_ack[0], syn_ack[1][14:])
    )
    flow, = PcapParser().parse(path).flows
    assert flow.total_frame_bytes == 80
    assert flow.handshake_rtt is None


def test_bad_frame_is_skipped_and_nonflow_bytes_are_retained(tmp_path, caplog):
    path = tmp_path / "mixed.pcap"
    arp = arp_packet()
    write_pcap(path, [(0, malformed_packet_bytes()), (0.5, arp), *handshake_packets()])
    capture = PcapParser().parse(path)
    assert capture.malformed_packet_count == 1
    assert capture.other_frame_bytes == len(arp)
    assert capture.flows[0].total_frame_bytes == 262
    assert path.name in caplog.text


@pytest.mark.parametrize("broken", ["missing", "header", "pcap_body", "pcapng_tail", "unsupported"])
def test_unreadable_capture_raises_with_filename(tmp_path, broken):
    path = tmp_path / "broken.capture"
    if broken == "header":
        path.write_bytes(truncated_record_pcap_bytes())
    elif broken == "pcap_body":
        write_pcap(path, handshake_packets())
        path.write_bytes(path.read_bytes()[:-1])
    elif broken == "pcapng_tail":
        path.write_bytes(pcapng_section_header_block() + pcapng_interface_description_block(101) + b"x")
    elif broken == "unsupported":
        write_pcap(path, [], linktype=999)

    with pytest.raises(PcapParseError, match=path.name):
        PcapParser().parse(path)
