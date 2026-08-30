#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import socket
import sys
import time


def server(address: str, port: int, count: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(count)
    print("LISTENING", flush=True)
    connections = []
    for _ in range(count):
        connection, _ = listener.accept()
        connections.append(connection)
    print(f"READY {len(connections)}", flush=True)
    time.sleep(30)


def client(address: str, port: int, count: int) -> None:
    connections = []
    for _ in range(count):
        connection = socket.create_connection((address, port), timeout=10)
        connection.settimeout(None)
        connections.append(connection)
    for _ in range(4):
        for connection in connections:
            connection.sendall(b"client-access-v46\n")
    print(f"READY {len(connections)}", flush=True)
    time.sleep(30)


if len(sys.argv) != 5 or sys.argv[1] not in {"server", "client"}:
    raise SystemExit("usage: sfo-flow-load.py server|client ADDRESS PORT COUNT")

role, host, port_text, count_text = sys.argv[1:]
(server if role == "server" else client)(host, int(port_text), int(count_text))
