import struct
import socket
from datetime import datetime
from typing import Optional, List, Dict, Any
from packetsentry.core.models import PacketMetadata

class PacketParser:
    """
    Decodes Ethernet, IPv4, TCP, UDP, ICMP, and DNS layers
    from raw byte frames or simulated packet logs.
    """

    @staticmethod
    def parse_raw_ethernet(raw_bytes: bytes) -> Optional[PacketMetadata]:
        if len(raw_bytes) < 14:
            return None

        # Ethernet header: Dest MAC (6), Src MAC (6), EtherType (2)
        eth_proto = struct.unpack("!H", raw_bytes[12:14])[0]

        # IPv4 (0x0800)
        if eth_proto == 0x0800:
            ip_header = raw_bytes[14:34]
            if len(ip_header) < 20:
                return None
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            ihl = (version_ihl & 0xF) * 4
            protocol_num = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            total_len = iph[2]

            transport_offset = 14 + ihl
            src_port = None
            dst_port = None
            tcp_flags = None
            proto_name = "IP"
            dns_q = None

            # TCP (6)
            if protocol_num == 6 and len(raw_bytes) >= transport_offset + 20:
                proto_name = "TCP"
                tcph = struct.unpack("!HHLLBBHHH", raw_bytes[transport_offset:transport_offset + 20])
                src_port = tcph[0]
                dst_port = tcph[1]
                flags = tcph[5]
                flag_list = []
                if flags & 0x02: flag_list.append("SYN")
                if flags & 0x10: flag_list.append("ACK")
                if flags & 0x01: flag_list.append("FIN")
                if flags & 0x04: flag_list.append("RST")
                if flags & 0x08: flag_list.append("PSH")
                if flags & 0x20: flag_list.append("URG")
                tcp_flags = ",".join(flag_list)

            # UDP (17)
            elif protocol_num == 17 and len(raw_bytes) >= transport_offset + 8:
                proto_name = "UDP"
                udph = struct.unpack("!HHHH", raw_bytes[transport_offset:transport_offset + 8])
                src_port = udph[0]
                dst_port = udph[1]

                # Check if DNS (port 53)
                if dst_port == 53 or src_port == 53:
                    proto_name = "DNS"
                    payload = raw_bytes[transport_offset + 8:]
                    dns_q = PacketParser._extract_dns_query(payload)

            # ICMP (1)
            elif protocol_num == 1:
                proto_name = "ICMP"

            return PacketMetadata(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_name,
                length=total_len,
                tcp_flags=tcp_flags,
                dns_query=dns_q
            )

        return None

    @staticmethod
    def _extract_dns_query(payload: bytes) -> Optional[str]:
        if len(payload) < 12:
            return None
        try:
            # Question section starts at byte 12
            idx = 12
            parts = []
            while idx < len(payload):
                length = payload[idx]
                if length == 0:
                    break
                idx += 1
                if idx + length > len(payload):
                    break
                parts.append(payload[idx:idx + length].decode("ascii", errors="ignore"))
                idx += length
            return ".".join(parts) if parts else None
        except Exception:
            return None
