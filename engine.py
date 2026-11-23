"""Detection engine: analyses packets and raises alerts based on rules.json."""
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
BRUTE_SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}


@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    message: str
    blockable: bool = True
    action: str = "none"


class DetectionEngine:
    def __init__(self, cfg, on_alert):
        self.th = cfg["thresholds"]
        self.on_alert = on_alert
        self.cooldown = cfg.get("alert_cooldown", 30)
        self.whitelist = set(cfg.get("whitelist_ips", []))
        self.blacklist = set(cfg.get("blacklist_ips", []))
        self.bad_ports = set(cfg.get("suspicious_ports", []))
        self.sigs = [(s["name"], re.compile(s["pattern"], re.I), s["severity"])
                     for s in cfg.get("signatures", [])]
        self.scan = defaultdict(deque)
        self.syn = defaultdict(deque)
        self.icmp = defaultdict(deque)
        self.udp = defaultdict(deque)
        self.brute = defaultdict(deque)
        self.arp_table = {}
        self.last = {}
        self.stats = Counter()

    # ---------- helpers ----------
    @staticmethod
    def _window(store, key, ts, window, item):
        dq = store[key]
        dq.append((ts, item))
        while dq and ts - dq[0][0] > window:
            dq.popleft()
        return dq

    def fire(self, rule, sev, ts, src, dst, dport, proto, msg, key=None, blockable=True):
        k = (rule, key or src)
        if ts - self.last.get(k, -1e18) < self.cooldown:
            return
        self.last[k] = ts
        self.stats[rule] += 1
        self.on_alert(Alert(ts, rule, sev, src, dst, dport, proto, msg, blockable))

    # ---------- main entry ----------
    def analyze(self, pkt):
        self.stats["packets"] += 1
        try:
            self._analyze(pkt)
        except Exception:
            self.stats["errors"] += 1

    def _analyze(self, pkt):
        ts = float(pkt.time)
        if pkt.haslayer(ARP):
            return self._arp(pkt[ARP], ts)
        if not pkt.haslayer(IP):
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        if src in self.whitelist:
            return
        if src in self.blacklist:
            self.fire("Blacklisted IP", "high", ts, src, dst, None, "IP",
                      f"Traffic from blacklisted address {src}")
        dport, proto = None, "IP"
        if pkt.haslayer(TCP):
            dport, proto = pkt[TCP].dport, "TCP"
            self._tcp(pkt[TCP], ts, src, dst)
        elif pkt.haslayer(UDP):
            dport, proto = pkt[UDP].dport, "UDP"
            self._udp(ts, src, dst, dport)
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            self._icmp(pkt[ICMP], ts, src, dst)
        if dport in self.bad_ports:
            self.fire("Suspicious Port", "medium", ts, src, dst, dport, proto,
                      f"Connection to commonly abused port {dport}")
        if pkt.haslayer(Raw):
            self._payload(pkt[Raw], ts, src, dst, proto, dport)

    # ---------- detectors ----------
    def _tcp(self, t, ts, src, dst):
        flags, dport = int(t.flags), t.dport
        syn_only = (flags & (SYN | ACK | FIN | RST)) == SYN
        kind = None
        if flags == 0:
            kind = "NULL"
        elif (flags & (FIN | PSH | URG)) == (FIN | PSH | URG):
            kind = "XMAS"
        elif flags == FIN:
            kind = "FIN"
        elif syn_only:
            kind = "SYN"

        if kind:  # port scan
            cfg = self.th["port_scan"]
            dq = self._window(self.scan, src, ts, cfg["window"], dport)
            ports = {p for _, p in dq}
            if len(ports) >= cfg["ports"]:
                self.fire("Port Scan", "high", ts, src, dst, dport, "TCP",
                          f"{kind} scan: {len(ports)} distinct ports in {cfg['window']}s")

        if syn_only:  # SYN flood (per victim)
            cfg = self.th["syn_flood"]
            dq = self._window(self.syn, dst, ts, cfg["window"], src)
            if len(dq) >= cfg["packets"]:
                nsrc = len({s for _, s in dq})
                self.fire("SYN Flood", "critical", ts, src, dst, dport, "TCP",
                          f"{len(dq)} SYN packets from {nsrc} source(s) in {cfg['window']}s",
                          key=dst, blockable=nsrc <= 3)
            if dport in BRUTE_SERVICES:  # brute force on login services
                cfg = self.th["brute_force"]
                dq = self._window(self.brute, (src, dst, dport), ts, cfg["window"], 1)
                if len(dq) >= cfg["attempts"]:
                    svc = BRUTE_SERVICES[dport]
                    self.fire(f"{svc} Brute Force", "high", ts, src, dst, dport, "TCP",
                              f"{len(dq)} connection attempts to {svc} in {cfg['window']}s",
                              key=(src, dst))

    def _udp(self, ts, src, dst, dport):
        cfg = self.th["udp_flood"]
        dq = self._window(self.udp, src, ts, cfg["window"], 1)
        if len(dq) >= cfg["packets"]:
            self.fire("UDP Flood", "high", ts, src, dst, dport, "UDP",
                      f"{len(dq)} UDP packets in {cfg['window']}s")

    def _icmp(self, ic, ts, src, dst):
        if ic.type != 8:  # echo request only
            return
        cfg = self.th["icmp_flood"]
        dq = self._window(self.icmp, src, ts, cfg["window"], 1)
        if len(dq) >= cfg["packets"]:
            self.fire("ICMP Flood", "high", ts, src, dst, None, "ICMP",
                      f"{len(dq)} ICMP echo requests in {cfg['window']}s")

    def _arp(self, a, ts):
        if a.op not in (1, 2) or a.psrc in ("", "0.0.0.0"):
            return
        known = self.arp_table.get(a.psrc)
        if known is None:
            self.arp_table[a.psrc] = a.hwsrc
        elif known != a.hwsrc:
            self.fire("ARP Spoofing", "critical", ts, a.psrc, a.pdst, None, "ARP",
                      f"{a.psrc} changed MAC {known} -> {a.hwsrc}", blockable=False)

    def _payload(self, raw, ts, src, dst, proto, dport):
        data = bytes(raw.load)[:4096].decode("latin-1")
        for name, rx, sev in self.sigs:
            if rx.search(data):
                self.fire(name, sev, ts, src, dst, dport, proto,
                          f"Signature '{name}' matched in payload")
