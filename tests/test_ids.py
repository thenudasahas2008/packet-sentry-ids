import json
from pathlib import Path
from datetime import datetime

root = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(root))

from packetsentry.core.models import PacketMetadata
from packetsentry.core.engine import IDSEngine
from packetsentry.detectors.dns_tunneling import DNSTunnelingDetector
from packetsentry.detectors.port_scan import PortScanDetector

def test_dns_tunneling_detection():
    detector = DNSTunnelingDetector()
    high_entropy_packet = PacketMetadata(
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=52000,
        dst_port=53,
        protocol="UDP",
        length=120,
        dns_query="dGhpcy1pcy1hbi1leGZpbHRyYXRpb24tdGVzdC1wYXlsb2Fk.c2.attacker.com"
    )
    alert = detector.process_packet(high_entropy_packet)
    assert alert is not None
    assert alert.category == "EXFILTRATION"
    assert alert.severity == "CRITICAL"
    assert alert.mitre_attack_id == "T1071.004"

def test_port_scan_detection_flow():
    engine = IDSEngine()
    sample_file = root / "samples" / "attack_traffic_sample.json"
    assert sample_file.exists()

    with open(sample_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        p = PacketMetadata(
            timestamp=datetime.fromisoformat(item["timestamp"]),
            src_ip=item["src_ip"],
            dst_ip=item["dst_ip"],
            src_port=item.get("src_port"),
            dst_port=item.get("dst_port"),
            protocol=item.get("protocol", "TCP"),
            length=item.get("length", 64),
            tcp_flags=item.get("tcp_flags"),
            dns_query=item.get("dns_query")
        )
        engine.inspect_packet(p)

    assert len(engine.alerts) >= 2
    rules = [a.rule_name for a in engine.alerts]
    assert any("Port Scan" in r for r in rules)
    assert any("DNS Tunneling" in r for r in rules)
