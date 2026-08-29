#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import socket
import struct
import sys


def mac_bytes(text):
    return bytes(int(part, 16) for part in text.split(":"))


def ethernet(destination, ethertype, payload):
    source = mac_bytes("02:00:00:00:00:42")
    return destination + source + struct.pack("!H", ethertype) + payload


def ipv4(protocol, payload=b"", total_length=None, ihl=5, fragment_offset=0):
    declared = total_length if total_length is not None else ihl * 4 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        declared,
        1,
        fragment_offset,
        64,
        protocol,
        0,
        ipaddress.IPv4Address("192.0.2.2").packed,
        ipaddress.IPv4Address("198.51.100.3").packed,
    )
    return header + payload


def ipv6(next_header, payload=b"", payload_length=None):
    declared = len(payload) if payload_length is None else payload_length
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        declared,
        next_header,
        64,
        ipaddress.IPv6Address("2001:db8:1::2").packed,
        ipaddress.IPv6Address("2001:db8:2::2").packed,
    ) + payload


def main():
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INTERFACE DESTINATION_MAC")
    interface = sys.argv[1]
    destination = mac_bytes(sys.argv[2])
    tcp = struct.pack("!HHIIHHHH", 12345, 443, 0, 0, (5 << 12) | 2, 65535, 0, 0)
    short_doff_tcp = struct.pack(
        "!HHIIHHHH", 12345, 443, 0, 0, (4 << 12) | 2, 65535, 0, 0
    )
    udp_short_length = struct.pack("!HHHH", 12345, 443, 7, 0)
    udp_long_length = struct.pack("!HHHH", 12345, 443, 20, 0)
    ipv6_fragment = struct.pack("!BBHI", 6, 0, 0, 1)
    frames = [
        # V41-SEC-001: truncated Ethernet. There is no source selector yet, so
        # this one safely returns before the parse_unsupported counter.
        b"\x00" * 10,
        # Truncated VLAN and IPv4 headers.
        ethernet(destination, 0x8100, b"\x00\x2a"),
        ethernet(destination, 0x0800, b"\x45" + b"\x00" * 9),
        # Invalid IPv4 IHL and protocol-declared total lengths.
        ethernet(destination, 0x0800, ipv4(6, ihl=4)),
        ethernet(destination, 0x0800, ipv4(6, total_length=10)),
        ethernet(destination, 0x0800, ipv4(6, total_length=100)),
        # Fragmentation, physically/declaratively truncated TCP, and bad doff.
        ethernet(destination, 0x0800, ipv4(6, tcp, fragment_offset=0x2000)),
        ethernet(destination, 0x0800, ipv4(6, b"\x00" * 4)),
        ethernet(destination, 0x0800, ipv4(6, tcp, total_length=30)),
        ethernet(destination, 0x0800, ipv4(6, short_doff_tcp)),
        # Physically truncated UDP and invalid short/long UDP lengths.
        ethernet(destination, 0x0800, ipv4(17, b"\x00" * 4)),
        ethernet(destination, 0x0800, ipv4(17, udp_short_length)),
        ethernet(destination, 0x0800, ipv4(17, udp_long_length)),
        # Truncated IPv6, declared payload mismatch, and unsupported extension
        # headers including Fragment.
        ethernet(destination, 0x86DD, b"\x60" + b"\x00" * 19),
        ethernet(destination, 0x86DD, ipv6(6, tcp, payload_length=10)),
        ethernet(destination, 0x86DD, ipv6(6, payload_length=100)),
        ethernet(destination, 0x86DD, ipv6(0, b"\x00" * 8)),
        ethernet(destination, 0x86DD, ipv6(44, ipv6_fragment)),
    ]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as raw:
        raw.bind((interface, 0))
        for frame in frames:
            raw.send(frame)
    print(len(frames))


if __name__ == "__main__":
    main()
