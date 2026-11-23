"""Network Intrusion Detection System - entry point.

Live monitoring : python main.py --iface "Wi-Fi"        (run as Admin/root)
Replay a pcap   : python main.py --pcap sample_attacks.pcap
List interfaces : python main.py --list-ifaces
"""
import argparse
import json
import logging
import os
import sys
import time

try:
    import colorama
    colorama.just_fix_windows_console()
except Exception:
    pass

from scapy.all import PcapReader, get_if_list, sniff

from ids.database import AlertDB
from ids.engine import DetectionEngine
from ids.response import ResponseEngine

COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[91m", "critical": "\033[95m"}
RESET = "\033[0m"


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    log = logging.getLogger("ids")
    log.setLevel(logging.INFO)
    fh = logging.FileHandler("logs/ids.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(fh)
    log.addHandler(sh)
    return log


def main():
    ap = argparse.ArgumentParser(description="Network Intrusion Detection System")
    ap.add_argument("--iface", help="interface to sniff (default: scapy default)")
    ap.add_argument("--pcap", help="analyse a pcap file instead of live traffic")
    ap.add_argument("--rules", default="rules.json")
    ap.add_argument("--db", default="alerts.db")
    ap.add_argument("--filter", default="", help="BPF filter, e.g. 'tcp or icmp'")
    ap.add_argument("--block", action="store_true",
                    help="really block attackers via firewall (default: dry-run)")
    ap.add_argument("--list-ifaces", action="store_true")
    args = ap.parse_args()

    if args.list_ifaces:
        print("\n".join(get_if_list()))
        return

    with open(args.rules, encoding="utf-8") as f:
        cfg = json.load(f)
    if args.block:
        cfg["response"]["dry_run"] = False

    log = setup_logging()
    db = AlertDB(args.db)
    responder = ResponseEngine(cfg["response"], cfg.get("whitelist_ips", []))

    def on_alert(a):
        a.action = responder.respond(a)
        db.add(a)
        t = time.strftime("%H:%M:%S", time.localtime(a.ts))
        c = COLORS.get(a.severity, "")
        log.warning("%s[%s] %-8s %-18s %s -> %s | %s | action: %s%s",
                    c, t, a.severity.upper(), a.rule, a.src_ip, a.dst_ip,
                    a.message, a.action, RESET)

    engine = DetectionEngine(cfg, on_alert)
    mode = f"pcap {args.pcap}" if args.pcap else f"live ({args.iface or 'default iface'})"
    log.info("NIDS started - mode: %s | response: %s", mode,
             "DRY-RUN" if cfg["response"]["dry_run"] else "ACTIVE BLOCKING")

    try:
        if args.pcap:
            with PcapReader(args.pcap) as reader:
                for pkt in reader:
                    engine.analyze(pkt)
        else:
            sniff(iface=args.iface, prn=engine.analyze, store=False, filter=args.filter or None)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        log.error("Permission denied - run as Administrator/root (and install Npcap on Windows).")
    finally:
        s = engine.stats
        log.info("Stopped. packets=%d alerts=%d errors=%d",
                 s["packets"], sum(v for k, v in s.items() if k not in ("packets", "errors")),
                 s["errors"])
        db.close()


if __name__ == "__main__":
    main()
