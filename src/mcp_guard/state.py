"""Local one-use operator approvals and payload-free audit records."""

import hashlib
import html
import json
import os
import sqlite3
import time
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def private_open(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    return fd


class Approvals:
    def __init__(self, path):
        self.path = str(path)
        os.close(private_open(path))
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS approvals (digest TEXT PRIMARY KEY, expires REAL NOT NULL)"
            )

    def grant(self, name, arguments, *, ttl=60, now=None):
        if not 0 < ttl <= 3600:
            raise ValueError("approval ttl must be between 0 and 3600")
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO approvals VALUES (?, ?)",
                (
                    fingerprint([name, arguments]),
                    (time.time() if now is None else now) + ttl,
                ),
            )

    def consume(self, name, arguments, *, now=None):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "DELETE FROM approvals WHERE digest = ? AND expires > ? RETURNING digest",
                (fingerprint([name, arguments]), time.time() if now is None else now),
            ).fetchone()
            return row is not None


class Audit:
    def __init__(self, path):
        self.path = Path(path)

    def record(self, method, decision, findings, message):
        event = {
            "schema_version": 1,
            "time": time.time(),
            "method": method[:200],
            "decision": decision,
            "findings": findings,
            "sha256": fingerprint(message),
        }
        with os.fdopen(private_open(self.path), "a") as stream:
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")


def render_audit(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        event = json.loads(line)
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(event.get(key, '')))}</td>"
                for key in ("time", "method", "decision", "findings", "sha256")
            )
            + "</tr>"
        )
    return (
        """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>MCP Guard audit</title><style>body{font:15px system-ui;margin:3rem;background:#0c1520;color:#e8eef5}table{border-collapse:collapse;width:100%}td,th{border:1px solid #405064;padding:.7rem;text-align:left;overflow-wrap:anywhere}h1{color:#5de0b4}</style><h1>MCP Guard / audit</h1><p>Payload-free local decision log. Timestamps are Unix seconds.</p><table><thead><tr><th>Time</th><th>Method</th><th>Decision</th><th>Findings</th><th>SHA-256</th></tr></thead><tbody>"""
        + "".join(rows)
        + "</tbody></table></html>"
    )
