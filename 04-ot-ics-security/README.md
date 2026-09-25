# 04 · OT / ICS Security: Modbus Monitoring & IEC 62443 Segmentation

**Proves:** Certified SCADA Security Architect (CSSA) skills and the ICS Security Workshop (Modbus/DNP3, Purdue model, Wireshark) — applied to a passive, defensive monitor.

This project is **defensive and passive**. It reads a network capture and alerts when traffic breaks a site's communication policy. It does not send anything to any device.

**What's here**

| Path | Purpose |
|---|---|
| [`docs/iec62443-zones-conduits.md`](docs/iec62443-zones-conduits.md) | Zone-and-conduit segmentation design (Purdue model) that the policy is derived from |
| [`policy.yaml`](policy.yaml) | The communication policy: which hosts may read/write, which registers, and safe value ranges |
| [`detector/modbus_ids.py`](detector/modbus_ids.py) | Passive Modbus/TCP monitor that enforces the policy on a capture |
| [`detector/pcap_io.py`](detector/pcap_io.py) | Dependency-free pcap reader/writer (stdlib only, so it runs on locked-down OT hosts) |
| [`data/make_sample.py`](data/make_sample.py) | Builds a small sample capture (normal polling + a few policy violations) |
| [`tests/test_modbus_ids.py`](tests/test_modbus_ids.py) | One test per detection rule, checked against known Modbus ADUs |

## Detection rules

| ID | Severity | Detects |
|---|---|---|
| R1 | HIGH | A host not on the allow-list speaking Modbus to the PLC (e.g. an IT host that crossed the boundary) |
| R2 | CRITICAL | A write function code from a host permitted only to read |
| R3 | CRITICAL | A register written to a value outside its engineering-safe range |
| R4 | HIGH | Diagnostics / device-ID / programming function codes from a host not allowed to use them |
| R5 | MEDIUM | A burst of exception responses (scanning or fuzzing) |
| R6 | MEDIUM | An unknown or reserved function code |

## Run

```bash
pip install pyyaml
python data/make_sample.py
python detector/modbus_ids.py data/sample_modbus.pcap
```

```text
[HIGH    ] R1 10.20.1.66 -> 10.20.2.20: host not in Modbus allow-list
[CRITICAL] R2 10.20.1.20 -> 10.20.2.20: FC6 Write Single Register from host not permitted to write
[CRITICAL] R3 10.20.1.10 -> 10.20.2.20: register 2 set to 900, safe range 5-60
[HIGH    ] R4 10.20.1.20 -> 10.20.2.20: FC8 Diagnostics
4 alerts
```

```bash
pytest -q    # 12 passed
```

## Scope & ethics

A lab built to demonstrate **detection and segmentation design**. The capture is synthetic test data generated locally; the addresses and the pumping station are fictional. There is no real equipment, and the tool only reads captures — it issues no commands.
