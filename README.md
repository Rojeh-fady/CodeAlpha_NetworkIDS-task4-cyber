# Network Intrusion Detection System (Python)

CodeAlpha Cybersecurity Internship - Task 4.

A network-based IDS written in Python with Scapy. It sniffs traffic (live or from a pcap),
applies configurable rules, stores alerts in SQLite, optionally blocks attackers through the
OS firewall, and shows everything in a Streamlit dashboard.

## Task requirements -> implementation
| Requirement | Where |
|---|---|
| Set up a network-based IDS | `main.py` + `ids/engine.py` (Scapy replaces Snort/Suricata with pure Python) |
| Configure rules and alerts | `rules.json` (thresholds, blacklist, ports, regex signatures) |
| Monitor traffic continuously | `sniff()` live capture in `main.py` |
| Response mechanisms | `ids/response.py` (temporary firewall block, auto-unblock) |
| Visualize attacks | `dashboard.py` (Streamlit) |

## Detections
Port scan (SYN/NULL/FIN/XMAS), SYN flood, ICMP flood, UDP flood, SSH/FTP/Telnet/RDP/SMB brute force,
ARP spoofing, blacklisted IPs, suspicious ports, and payload signatures (SQLi, XSS, path traversal,
command injection, NOP sled, scanner user-agents).

## Setup
```
pip install -r requirements.txt
```
Windows: install [Npcap](https://npcap.com) and run the terminal as Administrator. Linux: run with `sudo`.

## Usage
```
python simulate_attacks.py                    # builds sample_attacks.pcap (safe, offline)
python main.py --pcap sample_attacks.pcap     # analyse it
streamlit run dashboard.py                    # open the dashboard

python main.py --list-ifaces                  # live mode
python main.py --iface "Wi-Fi"
python main.py --iface "Wi-Fi" --block        # really block attackers (Admin/root)
```
By default the response engine runs in **dry-run** mode (logs what it would block).

## Structure
```
main.py  dashboard.py  simulate_attacks.py  rules.json
ids/engine.py  ids/response.py  ids/database.py
```
Only use on networks you own or are authorised to monitor.
