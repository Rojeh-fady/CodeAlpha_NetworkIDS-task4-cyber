"""SQLite storage for alerts (read by the dashboard)."""
import sqlite3
import threading


class AlertDB:
    def __init__(self, path="alerts.db"):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, rule TEXT, severity TEXT,
                src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, message TEXT, action TEXT)"""
        )
        self.conn.commit()

    def add(self, a):
        with self.lock:
            self.conn.execute(
                "INSERT INTO alerts(ts,rule,severity,src_ip,dst_ip,dst_port,proto,message,action)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (a.ts, a.rule, a.severity, a.src_ip, a.dst_ip,
                 a.dst_port, a.proto, a.message, a.action),
            )
            self.conn.commit()

    def close(self):
        self.conn.close()
