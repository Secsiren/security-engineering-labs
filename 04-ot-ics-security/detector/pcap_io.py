"""Minimal, dependency-free pcap reader/writer for Ethernet/IPv4/TCP Modbus.

Using the standard library only keeps the detector easy to audit and to run
on locked-down OT jump hosts where installing packages is not allowed.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Iterator

PCAP_GLOBAL = struct.Struct("<IHHiIII")
PCAP_REC = struct.Struct("<IIII")
MODBUS_PORT = 502


@dataclass(frozen=True)
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes


def _ipv4(src: str, dst: str, payload_len: int) -> bytes:
    total = 20 + payload_len
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))


def _tcp(sport: int, dport: int, seq: int) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0)


def write_pcap(path: str, packets: list[Packet]) -> None:
    with open(path, "wb") as fh:
        fh.write(PCAP_GLOBAL.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # linktype 1 = Ethernet
        for i, p in enumerate(packets):
            tcp = _tcp(p.sport, p.dport, 1000 + i) + p.payload
            ip = _ipv4(p.src, p.dst, len(tcp)) + tcp
            eth = b"\x00\x1b\x1b\x00\x00\x02" + b"\x00\x1b\x1b\x00\x00\x01" + b"\x08\x00" + ip
            sec = int(p.ts)
            usec = int(round((p.ts - sec) * 1_000_000))
            fh.write(PCAP_REC.pack(sec, usec, len(eth), len(eth)) + eth)


def read_pcap(path: str) -> Iterator[Packet]:
    with open(path, "rb") as fh:
        header = fh.read(PCAP_GLOBAL.size)
        magic = PCAP_GLOBAL.unpack(header)[0]
        if magic != 0xA1B2C3D4:
            raise ValueError("unsupported pcap (expected little-endian, microsecond)")
        while True:
            rec = fh.read(PCAP_REC.size)
            if len(rec) < PCAP_REC.size:
                return
            sec, usec, incl, _ = PCAP_REC.unpack(rec)
            frame = fh.read(incl)
            if len(frame) < 14 or frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 6:  # TCP only
                continue
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            tcp = ip[ihl:]
            sport, dport = struct.unpack("!HH", tcp[:4])
            data_off = (tcp[12] >> 4) * 4
            yield Packet(sec + usec / 1_000_000, src, dst, sport, dport, tcp[data_off:])
