import uuid
from datetime import timedelta
from collections import defaultdict
from typing import Optional
from packetsentry.core.models import PacketMetadata, ThreatAlert

class SynFloodDetector:
    """
    Detects volumetric half-open TCP SYN flood denial-of-service attacks.
    """
    SYN_BURST_THRESHOLD = 50
    WINDOW_SECONDS = 5

    def __init__(self):
        # Map: dst_ip -> list of (timestamp, src_ip)
        self.syn_table = defaultdict(list)

    def process_packet(self, packet: PacketMetadata) -> Optional[ThreatAlert]:
        if packet.protocol != "TCP" or not packet.tcp_flags:
            return None

        # Check for pure SYN
        if "SYN" in packet.tcp_flags and "ACK" not in packet.tcp_flags:
            dst = packet.dst_ip
            self.syn_table[dst].append((packet.timestamp, packet.src_ip))

            cutoff = packet.timestamp - timedelta(seconds=self.WINDOW_SECONDS)
            self.syn_table[dst] = [item for item in self.syn_table[dst] if item[0] >= cutoff]

            if len(self.syn_table[dst]) >= self.SYN_BURST_THRESHOLD:
                count = len(self.syn_table[dst])
                src_ips = list({item[1] for item in self.syn_table[dst]})
                self.syn_table[dst] = []

                return ThreatAlert(
                    alert_id=f"ALT-FLOOD-{uuid.uuid4().hex[:8]}",
                    timestamp=packet.timestamp,
                    rule_name="Volumetric TCP SYN Flood Attack",
                    category="DENIAL_OF_SERVICE",
                    severity="HIGH",
                    src_ip=src_ips[0] if len(src_ips) == 1 else "Distributed / Spoofed",
                    dst_ip=dst,
                    description=f"Destination {dst} targeted by a surge of {count} half-open SYN handshakes within {self.WINDOW_SECONDS}s.",
                    evidence={
                        "syn_count": count,
                        "window_seconds": self.WINDOW_SECONDS,
                        "unique_sources": len(src_ips)
                    },
                    mitre_attack_id="T1498.001",
                    recommended_action="Enable SYN cookies on target host; throttle inbound SYN rate at upstream firewall."
                )

        return None
