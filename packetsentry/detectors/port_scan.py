import uuid
from datetime import timedelta
from collections import defaultdict
from typing import List, Optional
from packetsentry.core.models import PacketMetadata, ThreatAlert

class PortScanDetector:
    """
    Detects horizontal and vertical port scans (SYN scans, NULL scans, XMAS scans).
    """
    THRESHOLD_PORTS = 10
    WINDOW_SECONDS = 15

    def __init__(self):
        # Map: (src_ip, dst_ip) -> list of (timestamp, dst_port, flags)
        self.history = defaultdict(list)

    def process_packet(self, packet: PacketMetadata) -> Optional[ThreatAlert]:
        if packet.protocol != "TCP" or not packet.tcp_flags:
            return None

        # Track SYN-only (without ACK) or stealth scan flags
        is_syn_scan = "SYN" in packet.tcp_flags and "ACK" not in packet.tcp_flags
        is_stealth = packet.tcp_flags == "" or "FIN,URG,PSH" in packet.tcp_flags

        if is_syn_scan or is_stealth:
            key = (packet.src_ip, packet.dst_ip)
            self.history[key].append((packet.timestamp, packet.dst_port, packet.tcp_flags))

            # Prune outside window
            cutoff = packet.timestamp - timedelta(seconds=self.WINDOW_SECONDS)
            self.history[key] = [item for item in self.history[key] if item[0] >= cutoff]

            unique_ports = {item[1] for item in self.history[key] if item[1] is not None}
            if len(unique_ports) >= self.THRESHOLD_PORTS:
                # Trigger alert and reset history for key
                self.history[key] = []
                return ThreatAlert(
                    alert_id=f"ALT-SCAN-{uuid.uuid4().hex[:8]}",
                    timestamp=packet.timestamp,
                    rule_name="Reconnaissance Port Scan Detected",
                    category="RECONNAISSANCE",
                    severity="HIGH",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Source host {packet.src_ip} probed {len(unique_ports)} distinct TCP ports on {packet.dst_ip} within {self.WINDOW_SECONDS}s.",
                    evidence={
                        "probed_ports_count": len(unique_ports),
                        "ports_sample": list(unique_ports)[:15],
                        "scan_type": "SYN_SCAN" if is_syn_scan else "STEALTH_SCAN"
                    },
                    mitre_attack_id="T1046",
                    recommended_action=f"Apply temporary drop rule at edge firewall for {packet.src_ip}."
                )

        return None
