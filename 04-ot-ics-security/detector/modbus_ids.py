"""Modbus/TCP intrusion detection for a (mock) water-utility pumping station.

Modbus has no authentication: any host that can reach TCP/502 can stop a pump.
This detector enforces the site's communication policy (zones & conduits from
docs/iec62443-zones-conduits.md) on captured traffic and raises alerts for:

  R1  unknown host talking Modbus to a PLC                       HIGH
  R2  write function code from a host not allowed to write        CRITICAL
  R3  write value outside the engineering safe range             CRITICAL
  R4  diagnostic / identification / programming function codes   HIGH
  R5  burst of exception responses (scanning or fuzzing)         MEDIUM
  R6  unknown or reserved function code                          MEDIUM

Usage: python detector/modbus_ids.py data/pumping_station.pcap --policy policy.yaml
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcap_io import MODBUS_PORT, read_pcap  # noqa: E402

READ_FCS = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers"}
WRITE_FCS = {5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils",
             16: "Write Multiple Registers", 22: "Mask Write Register", 23: "Read/Write Multiple Registers"}
SENSITIVE_FCS = {8: "Diagnostics", 17: "Report Server ID", 43: "Encapsulated Interface / Device ID",
                 90: "Vendor programming (e.g. Schneider UMAS)"}
KNOWN_FCS = set(READ_FCS) | set(WRITE_FCS) | set(SENSITIVE_FCS)


@dataclass
class Alert:
    rule: str
    severity: str
    ts: float
    src: str
    dst: str
    detail: str


def parse_request(payload: bytes):
    """Return (unit, fc, body) for a Modbus/TCP request ADU, or None."""
    if len(payload) < 8:
        return None
    _tid, proto, _length, unit = struct.unpack("!HHHB", payload[:7])
    if proto != 0:
        return None
    return unit, payload[7], payload[8:]


def write_targets(fc: int, body: bytes) -> list[tuple[int, int]]:
    """(address, value) pairs a write request will change."""
    if fc in (5, 6) and len(body) >= 4:
        addr, val = struct.unpack("!HH", body[:4])
        return [(addr, val)]
    if fc == 16 and len(body) >= 5:
        addr, qty, _nbytes = struct.unpack("!HHB", body[:5])
        vals = struct.unpack(f"!{qty}H", body[5:5 + 2 * qty])
        return [(addr + i, v) for i, v in enumerate(vals)]
    return []


def detect(pcap: str, policy: dict) -> list[Alert]:
    plcs = set(policy["plcs"])
    hosts = policy["hosts"]
    safe = {int(k): v for k, v in (policy.get("safe_ranges") or {}).items()}
    burst_n, burst_s = policy.get("exception_burst", [5, 10])
    alerts: list[Alert] = []
    exceptions: dict[str, deque] = defaultdict(deque)
    alerted_unknown: set[tuple[str, str]] = set()

    for p in read_pcap(pcap):
        # Responses from PLC: watch for exception bursts (fc | 0x80)
        if p.sport == MODBUS_PORT and p.src in plcs:
            if len(p.payload) >= 8 and p.payload[7] & 0x80:
                q = exceptions[p.dst]
                q.append(p.ts)
                while q and p.ts - q[0] > burst_s:
                    q.popleft()
                if len(q) == burst_n:
                    alerts.append(Alert("R5", "MEDIUM", p.ts, p.dst, p.src,
                                        f"{burst_n} exception responses in {burst_s}s (possible scan)"))
            continue
        if p.dport != MODBUS_PORT or p.dst not in plcs:
            continue
        req = parse_request(p.payload)
        if req is None:
            continue
        _unit, fc, body = req
        role = hosts.get(p.src)

        if role is None and (p.src, p.dst) not in alerted_unknown:
            alerted_unknown.add((p.src, p.dst))
            alerts.append(Alert("R1", "HIGH", p.ts, p.src, p.dst, "host not in Modbus allow-list"))
        allowed_fcs = set((role or {}).get("allowed_fcs", []))

        if fc not in KNOWN_FCS:
            alerts.append(Alert("R6", "MEDIUM", p.ts, p.src, p.dst, f"unknown function code {fc}"))
        elif fc in SENSITIVE_FCS and fc not in allowed_fcs:
            alerts.append(Alert("R4", "HIGH", p.ts, p.src, p.dst, f"FC{fc} {SENSITIVE_FCS[fc]}"))
        elif fc in WRITE_FCS:
            if fc not in allowed_fcs:
                alerts.append(Alert("R2", "CRITICAL", p.ts, p.src, p.dst,
                                    f"FC{fc} {WRITE_FCS[fc]} from host not permitted to write"))
            for addr, val in write_targets(fc, body):
                lo_hi = safe.get(addr)
                if lo_hi and not (lo_hi[0] <= val <= lo_hi[1]):
                    alerts.append(Alert("R3", "CRITICAL", p.ts, p.src, p.dst,
                                        f"register {addr} set to {val}, safe range {lo_hi[0]}-{lo_hi[1]}"))
    return alerts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--policy", default=str(Path(__file__).resolve().parents[1] / "policy.yaml"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    alerts = detect(args.pcap, yaml.safe_load(Path(args.policy).read_text()))
    if args.json:
        print(json.dumps([asdict(a) for a in alerts], indent=2))
    else:
        for a in alerts:
            print(f"[{a.severity:8}] {a.rule} {a.src} -> {a.dst}: {a.detail}")
        print(f"{len(alerts)} alerts")
    return 1 if any(a.severity == "CRITICAL" for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
