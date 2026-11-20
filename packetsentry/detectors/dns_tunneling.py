import math
import uuid
from typing import Optional
from packetsentry.core.models import PacketMetadata, ThreatAlert

class DNSTunnelingDetector:
    """
    Detects DNS tunneling, exfiltration, and C2 beacons using
    Shannon entropy analysis and query length thresholds.
    """
    SUBDOMAIN_LENGTH_THRESHOLD = 32
    ENTROPY_THRESHOLD = 3.6

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p, 2) for p in prob])
        return round(entropy, 2)

    def process_packet(self, packet: PacketMetadata) -> Optional[ThreatAlert]:
        if not packet.dns_query:
            return None

        query = packet.dns_query.lower()
        parts = query.split(".")
        if len(parts) < 2:
            return None

        # Analyze leftmost subdomain payload (the exfiltration carrier)
        subdomain = parts[0]
        length = len(subdomain)
        entropy = self.calculate_entropy(subdomain)

        if length >= self.SUBDOMAIN_LENGTH_THRESHOLD and entropy >= self.ENTROPY_THRESHOLD:
            return ThreatAlert(
                alert_id=f"ALT-DNS-{uuid.uuid4().hex[:8]}",
                timestamp=packet.timestamp,
                rule_name="DNS Tunneling / Data Exfiltration Signature",
                category="EXFILTRATION",
                severity="CRITICAL",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"High-entropy DNS query [{query}] indicates Base64/Hex encoded data exfiltration or active C2 channel.",
                evidence={
                    "query": query,
                    "subdomain_length": length,
                    "shannon_entropy": entropy,
                    "threshold_entropy": self.ENTROPY_THRESHOLD
                },
                mitre_attack_id="T1071.004",
                recommended_action=f"Sinkhole domain '{'.'.join(parts[1:])}' at internal recursive resolver; isolate host {packet.src_ip}."
            )

        return None
