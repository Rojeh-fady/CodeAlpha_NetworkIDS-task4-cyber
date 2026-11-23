"""Automatic response: temporarily block attacking IPs via the OS firewall."""
import ipaddress
import logging
import platform
import subprocess
import threading

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
log = logging.getLogger("ids")


class ResponseEngine:
    def __init__(self, cfg, whitelist=()):
        self.enabled = cfg.get("enabled", True)
        self.dry_run = cfg.get("dry_run", True)
        self.duration = cfg.get("block_seconds", 300)
        self.min_rank = RANK[cfg.get("min_severity", "high")]
        self.whitelist = set(whitelist)
        self.blocked = set()
        self.windows = platform.system() == "Windows"

    def _cmd(self, ip, add):
        if self.windows:
            name = f"name=IDS_BLOCK_{ip}"
            if add:
                return ["netsh", "advfirewall", "firewall", "add", "rule", name,
                        "dir=in", "action=block", f"remoteip={ip}"]
            return ["netsh", "advfirewall", "firewall", "delete", "rule", name]
        return ["iptables", "-I" if add else "-D", "INPUT", "-s", ip, "-j", "DROP"]

    def respond(self, alert):
        if not (self.enabled and alert.blockable
                and RANK.get(alert.severity, 0) >= self.min_rank):
            return "none"
        ip = alert.src_ip
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "none"
        if ip in self.whitelist or ip in self.blocked:
            return "none"
        if self.dry_run:
            self.blocked.add(ip)
            return f"DRY-RUN: would block {ip} for {self.duration}s"
        try:
            subprocess.run(self._cmd(ip, True), check=True, capture_output=True)
        except Exception as e:
            log.error("Block failed for %s: %s (run as Administrator/root)", ip, e)
            return "BLOCK FAILED"
        self.blocked.add(ip)
        t = threading.Timer(self.duration, self.unblock, args=(ip,))
        t.daemon = True
        t.start()
        return f"BLOCKED {ip} for {self.duration}s"

    def unblock(self, ip):
        try:
            subprocess.run(self._cmd(ip, False), check=True, capture_output=True)
            log.info("Unblocked %s", ip)
        except Exception as e:
            log.error("Unblock failed for %s: %s", ip, e)
        self.blocked.discard(ip)
