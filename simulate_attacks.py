"""Generates sample_attacks.pcap with benign + malicious traffic (offline, harmless).
Use it to test the IDS without touching a real network:
    python simulate_attacks.py && python main.py --pcap sample_attacks.pcap
"""
import random
import time

from scapy.all import ARP, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

VICTIM, VMAC = "192.168.1.10", "aa:bb:cc:00:00:10"
pkts, clock = [], time.time() - 120


def add(p, dt=0.05):
    global clock
    clock += dt
    p = Ether(dst=VMAC) / p
    p.time = clock
    pkts.append(p)


def http(src, payload, sport=None):
    add(IP(src=src, dst=VICTIM) / TCP(sport=sport or random.randint(1025, 60000),
        dport=80, flags="PA") / Raw(payload.encode()), 0.2)


# 1) normal traffic
for i in range(30):
    http("192.168.1.20", "GET /index.html HTTP/1.1\r\nHost: site\r\n\r\n")
add(IP(src="192.168.1.20", dst=VICTIM) / TCP(dport=443, flags="S"))

# 2) SYN port scan
for p in range(1, 41):
    add(IP(src="10.0.0.66", dst=VICTIM) / TCP(sport=40000, dport=p, flags="S"), 0.05)

# 3) XMAS stealth scan
for p in range(100, 125):
    add(IP(src="10.0.0.67", dst=VICTIM) / TCP(sport=40001, dport=p, flags="FPU"), 0.05)

# 4) SYN flood from one spoofed source
for _ in range(150):
    add(IP(src="10.0.0.200", dst=VICTIM) / TCP(sport=random.randint(1025, 65000), dport=80, flags="S"), 0.01)

# 5) ICMP flood
for _ in range(80):
    add(IP(src="10.0.0.77", dst=VICTIM) / ICMP(type=8), 0.02)

# 6) SSH brute force
for _ in range(12):
    add(IP(src="10.0.0.88", dst=VICTIM) / TCP(sport=random.randint(1025, 65000), dport=22, flags="S"), 1)

# 7) web attacks
http("10.0.0.99", "GET /login?user=admin' OR '1'='1 HTTP/1.1\r\n\r\n")
http("10.0.0.100", "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n")
http("10.0.0.101", "GET /../../../etc/passwd HTTP/1.1\r\n\r\n")
http("10.0.0.102", "GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n")

# 8) ARP spoofing
add(ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:00:00:01", pdst=VICTIM), 0.5)
add(ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01", pdst=VICTIM), 0.5)

# 9) blacklisted IP + suspicious port
add(IP(src="203.0.113.50", dst=VICTIM) / TCP(dport=8080, flags="S"))
add(IP(src="10.0.0.120", dst=VICTIM) / TCP(dport=4444, flags="S"))

# 10) UDP flood
for _ in range(250):
    add(IP(src="10.0.0.130", dst=VICTIM) / UDP(sport=5000, dport=53) / Raw(b"x"), 0.005)

wrpcap("sample_attacks.pcap", pkts)
print(f"sample_attacks.pcap created with {len(pkts)} packets")
