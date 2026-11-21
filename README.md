# PacketSentry — Light-speed Network Packet Analyzer & Anomaly IDS

[![IDS](https://img.shields.io/badge/Network%20Security-IDS-cyan.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](#)
[![MITRE](https://img.shields.io/badge/MITRE-T1046%20%7C%20T1071-red.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)

PacketSentry is a high-efficiency network intrusion detection system (NIDS) and protocol analyzer engine. It performs behavioral network stream analysis to detect:

- **Horizontal & Vertical Port Scans**: SYN, FIN, NULL, and XMAS stealth sweeps (MITRE T1046).
- **DNS Tunneling & Data Exfiltration**: Shannon entropy computation on domain labels (MITRE T1071.004).
- **Volumetric SYN Floods**: Half-open TCP handshake burst monitoring (MITRE T1498.001).

---

## Quickstart

### Installation
```bash
git clone https://github.com/thenudasahas2008/packet-sentry-ids.git
cd packet-sentry-ids
pip install -r requirements.txt
```

### Inspect Packet Telemetry
```bash
python -m packetsentry.cli --file samples/attack_traffic_sample.json
```

### Run Tests
```bash
pytest -v tests
```
