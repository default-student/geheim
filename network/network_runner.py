#!/usr/bin/env python3
"""Run pinned bw in a network namespace through one hard-coded Tailscale relay."""

from __future__ import annotations

import os
from pathlib import Path
import selectors
import signal
import socketserver
import subprocess
import sys
import threading
import urllib.request


TARGET_HOST = "vaultwarden.example.com"
TARGET_PORT = "443"
TAILSCALE = "/usr/bin/tailscale"
BW_VERSION = "2026.4.2"


class Relay(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = subprocess.Popen(
            [TAILSCALE, "nc", TARGET_HOST, TARGET_PORT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert upstream.stdin is not None and upstream.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(self.request, selectors.EVENT_READ, "client")
        selector.register(upstream.stdout, selectors.EVENT_READ, "upstream")
        try:
            try:
                while True:
                    events = selector.select(timeout=30)
                    if not events and upstream.poll() is not None:
                        break
                    for key, _ in events:
                        if key.data == "client":
                            chunk = self.request.recv(65536)
                            if not chunk:
                                return
                            upstream.stdin.write(chunk)
                            upstream.stdin.flush()
                        else:
                            chunk = os.read(upstream.stdout.fileno(), 65536)
                            if not chunk:
                                return
                            self.request.sendall(chunk)
            except (ConnectionError, BrokenPipeError, OSError):
                return
        finally:
            selector.close()
            try:
                upstream.stdin.close()
            except OSError:
                pass
            if upstream.poll() is None:
                upstream.terminate()
                try:
                    upstream.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    upstream.kill()
                    upstream.wait()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        return


def expected_bw() -> Path:
    return Path(__file__).resolve().parents[1] / f"bw-{BW_VERSION}" / "bw"


def start_server() -> tuple[Server, threading.Thread]:
    server = Server(("127.0.0.1", 443), Relay)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    return server, thread


def self_test() -> int:
    server, thread = start_server()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"https://{TARGET_HOST}/", timeout=10) as response:
            if response.status != 200:
                return 1
        try:
            opener.open("https://example.com/", timeout=3)
        except Exception:
            pass
        else:
            return 1
        print("vaultwarden-relay=reachable")
        print("general-network=blocked")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    executable = Path(sys.argv[1]).resolve()
    if executable != expected_bw() or not executable.is_file():
        return 2
    server, thread = start_server()
    child: subprocess.Popen | None = None

    def forward(signum, frame):
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    old_term = signal.signal(signal.SIGTERM, forward)
    old_hup = signal.signal(signal.SIGHUP, forward)
    try:
        child = subprocess.Popen(sys.argv[1:])
        return child.wait()
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGHUP, old_hup)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
