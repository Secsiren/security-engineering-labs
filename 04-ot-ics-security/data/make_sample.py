"""Build a small sample Modbus/TCP capture so the detector has data to run on.

The capture is neutral test data: mostly normal supervisory polling, with a few
packets that violate the site communication policy (an unlisted host, a
read-only host issuing a write, an out-of-range setpoint, and a diagnostics
request). It exists so `modbus_ids.py` produces visible output in the README;
it is not a scenario or a script for causing any effect on real equipment.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "detector"))
from pcap_io import MODBUS_PORT, Packet, write_pcap  # noqa: E402

PLC, HMI, HIST, ENG, UNLISTED = "10.20.2.20", "10.20.1.10", "10.20.1.20", "10.20.1.30", "10.20.1.66"
T0 = 1_760_000_000.0


def req(fc: int, body: bytes, tid: int = 1) -> bytes:
    pdu = bytes([fc]) + body
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def to_plc(src, payload, ts):
    return Packet(ts, src, PLC, 50000, MODBUS_PORT, payload)


def build() -> list[Packet]:
    p: list[Packet] = []
    # Normal supervisory polling (allowed reads and in-range setpoints)
    for i in range(6):
        p.append(to_plc(HMI, req(3, struct.pack("!HH", 0, 4)), T0 + i))
        p.append(to_plc(HIST, req(4, struct.pack("!HH", 0, 4)), T0 + i + 0.2))
    p.append(to_plc(HMI, req(6, struct.pack("!HH", 1, 500)), T0 + 7))   # setpoint in range
    # Policy violations for the detector to catch:
    p.append(to_plc(UNLISTED, req(3, struct.pack("!HH", 0, 2)), T0 + 8))   # R1 unlisted host
    p.append(to_plc(HIST, req(6, struct.pack("!HH", 0, 1)), T0 + 9))       # R2 read-only host writes
    p.append(to_plc(HMI, req(6, struct.pack("!HH", 2, 900)), T0 + 10))     # R3 out-of-range value
    p.append(to_plc(HIST, req(8, struct.pack("!HH", 4, 0)), T0 + 11))      # R4 diagnostics (not permitted for historian)
    return p


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "sample_modbus.pcap"
    write_pcap(str(out), build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
