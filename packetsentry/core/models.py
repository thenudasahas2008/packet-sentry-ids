from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class PacketMetadata:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP, ARP
    length: int
    tcp_flags: Optional[str] = None  # SYN, ACK, FIN, RST, PSH, URG
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    arp_op: Optional[str] = None  # REQUEST, REPLY
    arp_mac: Optional[str] = None

@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: datetime
    rule_name: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    src_ip: str
    dst_ip: str
    description: str
    evidence: Dict[str, Any]
    mitre_attack_id: str
    recommended_action: str
