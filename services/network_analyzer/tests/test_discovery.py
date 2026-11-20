import hashlib
from pathlib import Path

from pcap.discovery import discover_pcap_files
from pcap.models import DiscoveredPcap


def test_discovers_capture_files_in_filename_order(tmp_path: Path):
    scenario = tmp_path / "Bale" / "1mb"
    scenario.mkdir(parents=True)
    captures = [
        ("a.pcapng", b"first"),
        ("b.pcap", b"second"),
        ("c.PCAPNG", b"third"),
    ]
    for name, content in reversed(captures):
        (scenario / name).write_bytes(content)
    (scenario / "notes.txt").write_text("notes")
    nested = scenario / "ignored.pcapng"
    nested.mkdir()
    (nested / "nested.pcap").write_bytes(b"nested")

    assert discover_pcap_files(tmp_path) == [
        DiscoveredPcap(
            app_name="Bale",
            scenario="1mb",
            pcap_path=scenario / name,
            pcap_hash=hashlib.sha256(content).hexdigest(),
        )
        for name, content in captures
    ]
