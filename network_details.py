#!/usr/bin/env python3
"""Local server/network details wrapper for system-config-inspector.

Uses only Python's standard library and local kernel/filesystem information.
No public-IP lookup, DNS query, telemetry, or external HTTP request is made.
The existing system_info report is reused unchanged and extended with a
SERVER / NETWORK IDENTITY section.
"""
from __future__ import annotations

import argparse
import html
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import system_info

UNKNOWN = system_info.UNKNOWN


def read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return ""


def interface_details() -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    base = Path("/sys/class/net")
    try:
        names = sorted(p.name for p in base.iterdir() if p.is_dir())
    except OSError:
        names = []
    for name in names:
        mac = read(base / name / "address").strip() or UNKNOWN
        state = read(base / name / "operstate").strip() or UNKNOWN
        mtu = read(base / name / "mtu").strip() or UNKNOWN
        result.append((name, state, f"MAC={mac}; MTU={mtu}"))
    return result


def local_ipv4() -> list[str]:
    found: set[str] = set()
    # Kernel routing trie contains local addresses without making any network call.
    text = read("/proc/net/fib_trie")
    for line in text.splitlines():
        value = line.strip()
        if not value.startswith("|-- "):
            continue
        ip = value[4:].strip()
        if ip.count(".") != 3:
            continue
        if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("255."):
            continue
        try:
            socket.inet_aton(ip)
        except OSError:
            continue
        found.add(ip)
    if found:
        return sorted(found)
    # Conservative fallback: hostname resolution only; no external query is made.
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if not ip.startswith("127."):
                found.add(ip)
    except OSError:
        pass
    return sorted(found)


def local_ipv6() -> list[str]:
    found: set[str] = set()
    for line in read("/proc/net/if_inet6").splitlines():
        fields = line.split()
        if not fields:
            continue
        raw = fields[0]
        if len(raw) != 32:
            continue
        try:
            ip = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(raw))
        except (ValueError, OSError):
            continue
        if ip != "::1":
            found.add(ip)
    return sorted(found)


def default_gateway() -> str:
    for line in read("/proc/net/route").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[1] != "00000000":
            continue
        try:
            raw = int(fields[2], 16)
            return socket.inet_ntoa(raw.to_bytes(4, "little"))
        except (ValueError, OSError, OverflowError):
            continue
    return UNKNOWN


def dns_servers() -> list[str]:
    result: list[str] = []
    for line in read("/etc/resolv.conf").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].lower() == "nameserver":
            result.append(fields[1])
    return list(dict.fromkeys(result))


def server_identity() -> str:
    lines: list[str] = []
    lines.append("================ SERVER / NETWORK IDENTITY ================")
    lines.append(f"Server hostname                   {socket.gethostname() or UNKNOWN}")
    lines.append(f"Server local IPv4                  {', '.join(local_ipv4()) or UNKNOWN}")
    lines.append(f"Server local IPv6                  {', '.join(local_ipv6()) or UNKNOWN}")
    lines.append(f"Default gateway                    {default_gateway()}")
    lines.append(f"DNS nameservers                    {', '.join(dns_servers()) or UNKNOWN}")
    port = os.environ.get("PORT")
    lines.append(f"Service port                       {port if port else '10000 (fallback)'}")
    lines.append("Bind address                       0.0.0.0")
    lines.append("Public IP                          Not queried (no external network requests)")
    lines.append("Public IP source                   None; external lookup disabled")
    lines.append("Network inspection                 Local kernel/filesystem only")
    lines.append("\nInterfaces")
    interfaces = interface_details()
    if not interfaces:
        lines.append(f"  {UNKNOWN}")
    else:
        for name, state, extra in interfaces:
            lines.append(f"  {name:<32} state={state}; {extra}")
    return "\n".join(lines)


def full_report() -> str:
    return system_info.render_report().rstrip() + "\n\n" + server_identity() + "\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "SystemConfigInspector/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/":
            body = full_report().encode("utf-8", "replace")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404, "Not Found")

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if self.path == "/":
            body = full_report().encode("utf-8", "replace")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        self.send_error(404, "Not Found")

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[system-config-inspector] {fmt % args}")


def serve() -> None:
    port = int(os.environ.get("PORT", "10000"))
    report = full_report()
    print(report, end="")
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    stop = threading.Event()

    def shutdown() -> None:
        if not stop.is_set():
            stop.set()
            server.shutdown()

    import signal
    signal.signal(signal.SIGTERM, lambda *_: shutdown())
    signal.signal(signal.SIGINT, lambda *_: shutdown())
    print(f"[system-config-inspector] Plain-text report server listening on 0.0.0.0:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        print("[system-config-inspector] Server stopped cleanly.")


def main() -> int:
    parser = argparse.ArgumentParser(description="System configuration inspector")
    parser.add_argument("--once", action="store_true", help="print the report and exit")
    parser.add_argument("--serve", action="store_true", help="serve the same plain-text report over HTTP")
    args = parser.parse_args()
    if args.serve:
        serve()
    else:
        print(full_report(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
