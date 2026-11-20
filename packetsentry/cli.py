import argparse
import json
from datetime import datetime
from packetsentry.core.models import PacketMetadata
from packetsentry.core.engine import IDSEngine

def main():
    parser = argparse.ArgumentParser(
        description="PacketSentry — Light-speed Network Packet Analyzer & Anomaly IDS"
    )
    parser.add_argument("--file", help="Path to JSON packet stream log file", default=None)
    args = parser.parse_args()

    engine = IDSEngine()

    print("="*65)
    print("PACKETSENTRY // NETWORK INTRUSION DETECTION ENGINE")
    print("="*65)
    print("Active Detection Modules: Port Scan, DNS Tunneling, SYN Flood")

    if args.file:
        print(f"[*] Reading telemetry stream from: {args.file}")
        with open(args.file, "r", encoding="utf-8") as f:
            raw_packets = json.load(f)

        for p_data in raw_packets:
            meta = PacketMetadata(
                timestamp=datetime.fromisoformat(p_data["timestamp"]),
                src_ip=p_data["src_ip"],
                dst_ip=p_data["dst_ip"],
                src_port=p_data.get("src_port"),
                dst_port=p_data.get("dst_port"),
                protocol=p_data.get("protocol", "TCP"),
                length=p_data.get("length", 64),
                tcp_flags=p_data.get("tcp_flags"),
                dns_query=p_data.get("dns_query")
            )
            alerts = engine.inspect_packet(meta)
            for a in alerts:
                print(f"[!] [{a.severity}] {a.rule_name} | {a.src_ip} -> {a.dst_ip}")
                print(f"    MITRE: {a.mitre_attack_id} | {a.description}\n")

        print("="*65)
        print(f"Inspection Complete: {engine.total_packets_inspected} packets processed. {len(engine.alerts)} threats detected.")
    else:
        print("[*] Ready. Provide --file <packet_log.json> to execute packet analysis.")

if __name__ == "__main__":
    main()
