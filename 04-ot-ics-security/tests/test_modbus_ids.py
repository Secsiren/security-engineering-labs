"""Tests for the Modbus policy monitor.

Test data is built inline as small Modbus/TCP request and response ADUs, one
per rule, so each detection is checked against a known input. The packets are
neutral protocol samples used to exercise the detector; the point of the lab is
the monitoring logic, not any particular scenario.
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detector"))
from pcap_io import MODBUS_PORT, Packet, write_pcap  # noqa: E402
import modbus_ids as ids  # noqa: E402
import yaml  # noqa: E402

PLC = "10.20.2.20"
HMI = "10.20.1.10"
HIST = "10.20.1.20"
UNKNOWN = "10.20.1.66"
POLICY = yaml.safe_load((ROOT / "policy.yaml").read_text())
T0 = 1_760_000_000.0


def req(fc: int, body: bytes, tid: int = 1) -> bytes:
    """Build a Modbus/TCP request ADU (MBAP header + PDU)."""
    pdu = bytes([fc]) + body
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def exc(fc: int, code: int = 2) -> bytes:
    """Build a Modbus/TCP exception response ADU."""
    pdu = bytes([fc | 0x80, code])
    return struct.pack("!HHHB", 1, 0, len(pdu) + 1, 1) + pdu


def to_plc(src: str, payload: bytes, ts: float) -> Packet:
    return Packet(ts, src, PLC, 50000, MODBUS_PORT, payload)


def from_plc(dst: str, payload: bytes, ts: float) -> Packet:
    return Packet(ts, PLC, dst, MODBUS_PORT, 50000, payload)


def run(packets):
    p = Path("/tmp/claude-0/_modbus_test.pcap")
    p.parent.mkdir(parents=True, exist_ok=True)
    write_pcap(str(p), packets)
    return ids.detect(str(p), POLICY)


def rules(alerts):
    return [a.rule for a in alerts]


def test_normal_traffic_has_no_alerts():
    pkts = [
        to_plc(HMI, req(3, struct.pack("!HH", 0, 4)), T0),       # read holding registers
        from_plc(HMI, req(3, b"\x08" + b"\x00" * 8), T0 + 0.1),  # response
        to_plc(HIST, req(4, struct.pack("!HH", 0, 4)), T0 + 1),  # historian read
        to_plc(HMI, req(6, struct.pack("!HH", 1, 500)), T0 + 2), # setpoint within safe range
    ]
    assert run(pkts) == []


def test_R1_unknown_host_flagged_once():
    pkts = [to_plc(UNKNOWN, req(3, struct.pack("!HH", 0, 2)), T0),
            to_plc(UNKNOWN, req(3, struct.pack("!HH", 0, 2)), T0 + 1)]
    alerts = run(pkts)
    assert rules(alerts).count("R1") == 1  # deduplicated per host pair


def test_R2_write_from_read_only_host_is_critical():
    # Historian is read-only in policy; a write must be flagged CRITICAL.
    pkts = [to_plc(HIST, req(6, struct.pack("!HH", 0, 1)), T0)]
    alerts = run(pkts)
    a = [x for x in alerts if x.rule == "R2"]
    assert a and a[0].severity == "CRITICAL"


def test_R3_out_of_range_write_is_critical():
    # Register 2 safe range is 5-60; 900 is outside it.
    pkts = [to_plc(HMI, req(6, struct.pack("!HH", 2, 900)), T0)]
    alerts = run(pkts)
    a = [x for x in alerts if x.rule == "R3"]
    assert a and a[0].severity == "CRITICAL" and "900" in a[0].detail


def test_R3_in_range_write_allowed():
    pkts = [to_plc(HMI, req(6, struct.pack("!HH", 2, 30)), T0)]
    assert "R3" not in rules(run(pkts))


def test_R3_multi_register_write_checks_each_value():
    # FC16 write of two registers, second one (register 3) out of range.
    body = struct.pack("!HHB", 2, 2, 4) + struct.pack("!HH", 30, 9000)
    pkts = [to_plc(POLICY_ENG := "10.20.1.30", req(16, body), T0)]
    assert "R3" in rules(run(pkts))


def test_R4_sensitive_function_code_flagged():
    # FC8 diagnostics from the HMI (not permitted FC8 in policy).
    pkts = [to_plc(HMI, req(8, struct.pack("!HH", 4, 0)), T0)]
    assert "R4" in rules(run(pkts))


def test_R5_exception_burst_flagged():
    pkts = [from_plc(HMI, exc(3), T0 + i * 0.5) for i in range(5)]
    assert "R5" in rules(run(pkts))


def test_R5_below_threshold_not_flagged():
    pkts = [from_plc(HMI, exc(3), T0 + i * 0.5) for i in range(4)]
    assert "R5" not in rules(run(pkts))


def test_R6_unknown_function_code_flagged():
    pkts = [to_plc(HMI, req(99, b"\x00\x00"), T0)]
    assert "R6" in rules(run(pkts))


def test_engineering_workstation_may_write_multiple():
    # Eng workstation is allowed FC16 within range: no R2, no R3.
    body = struct.pack("!HHB", 0, 1, 2) + struct.pack("!H", 1)
    pkts = [to_plc("10.20.1.30", req(16, body), T0)]
    assert rules(run(pkts)) == []


def test_exit_code_nonzero_on_critical(capsys):
    p = Path("/tmp/claude-0/_modbus_cli.pcap")
    write_pcap(str(p), [to_plc(HIST, req(6, struct.pack("!HH", 0, 1)), T0)])
    assert ids.main([str(p), "--policy", str(ROOT / "policy.yaml")]) == 1
