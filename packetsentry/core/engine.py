from typing import List
from packetsentry.core.models import PacketMetadata, ThreatAlert
from packetsentry.detectors.port_scan import PortScanDetector
from packetsentry.detectors.dns_tunneling import DNSTunnelingDetector
from packetsentry.detectors.syn_flood import SynFloodDetector

class IDSEngine:
    def __init__(self):
        self.detectors = [
            PortScanDetector(),
            DNSTunnelingDetector(),
            SynFloodDetector()
        ]
        self.alerts: List[ThreatAlert] = []
        self.total_packets_inspected: int = 0

    def inspect_packet(self, packet: PacketMetadata) -> List[ThreatAlert]:
        self.total_packets_inspected += 1
        new_alerts = []

        for detector in self.detectors:
            alert = detector.process_packet(packet)
            if alert:
                new_alerts.append(alert)
                self.alerts.append(alert)

        return new_alerts
