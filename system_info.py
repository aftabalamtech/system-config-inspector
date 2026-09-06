#!/usr/bin/env python3
"""Portable, dependency-free, read-only Linux runtime inspector."""

from __future__ import annotations

import contextlib
import getpass
import http.server
import io
import math
import os
import platform
import re
import shutil
import signal
import socket
import socketserver
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Callable

UNKNOWN = "Unknown / Not exposed"
UNLIMITED = "Unlimited / No enforced limit"

# Only these environment variables are eligible for display. Values are still
# bounded and filtered; an allowlist is safer than printing the environment.
SAFE_ENVIRONMENT_NAMES = {
    "PORT", "RENDER", "RENDER_CPU_COUNT", "RENDER_SERVICE_NAME",
    "RENDER_SERVICE_TYPE", "RENDER_REGION", "RENDER_GIT_BRANCH",
    "RENDER_GIT_COMMIT", "AWS_REGION", "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME", "K_SERVICE", "K_REVISION", "DYNO",
    "HEROKU_APP_NAME", "VERCEL", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME",
    "GITHUB_ACTIONS", "CI", "NETLIFY", "CODEBUILD_BUILD_ARN",
}
SECRET_NAME_RE = re.compile(
    r"(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|APIKEY|AUTH|PRIVATE[_-]?KEY|"
    r"ACCESS[_-]?KEY|CREDENTIAL|DATABASE[_-]?URL|CONNECTION[_-]?STRING|JWT|"
    r"COOKIE|SESSION|CERT|SSH)", re.IGNORECASE,
)


def safe_call(function: Callable[[], Any], default: Any = UNKNOWN) -> Any:
    """Run one optional collector without allowing it to affect other output."""
    try:
        return function()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return default


def read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError, UnicodeError):
        return None


def first_line(path: str | Path) -> str | None:
    content = read_text(path)
    if not content:
        return None
    lines = content.splitlines()
    return lines[0].strip() if lines else None


def read_kv_file(path: str | Path, separator: str = "=") -> dict[str, str]:
    result: dict[str, str] = {}
    content = read_text(path)
    if not content:
        return result
    for line in content.splitlines():
        if separator not in line:
            continue
        key, value = line.split(separator, 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def parse_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return None


def parse_float(value: Any) -> float | None:
    try:
        number = float(str(value).strip())
        return number if math.isfinite(number) else None
    except (TypeError, ValueError, OverflowError):
        return None


def parse_limit(value: str | None) -> int | None:
    """Parse cgroup numeric limits; None means missing or unlimited."""
    if value is None or value.strip().lower() in {"max", "unlimited", "none", "-1"}:
        return None
    return parse_int(value)


def format_bytes(value: int | float | None, show_raw: bool = True) -> str:
    if value is None or value < 0:
        return UNKNOWN
    number = float(value)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    index = 0
    while number >= 1024.0 and index < len(units) - 1:
        number /= 1024.0
        index += 1
    formatted = f"{number:.1f} {units[index]}"
    return f"{formatted} ({int(value):,} bytes)" if show_raw else formatted


def format_limit(value: str | None) -> str:
    if value is None:
        return UNKNOWN
    if value.strip().lower() in {"max", "unlimited", "none", "-1"}:
        return UNLIMITED
    numeric = parse_limit(value)
    return format_bytes(numeric) if numeric is not None else UNKNOWN


def format_uptime() -> str:
    raw = first_line("/proc/uptime")
    seconds = parse_float(raw.split()[0]) if raw else None
    if seconds is None or seconds < 0:
        return UNKNOWN
    total = int(seconds)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = ([f"{days}d"] if days else []) + ([f"{hours}h"] if hours or days else [])
    parts += ([f"{minutes}m"] if minutes or hours or days else []) + [f"{secs}s"]
    return " ".join(parts)


def parse_meminfo() -> dict[str, int]:
    result: dict[str, int] = {}
    content = read_text("/proc/meminfo") or ""
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields = value.strip().split()
        number = parse_int(fields[0]) if fields else None
        if number is not None:
            # Linux meminfo values are normally KiB; byte fields are not used here.
            result[key.strip()] = number * 1024 if len(fields) > 1 and fields[1].lower() == "kb" else number
    return result


def cpu_model() -> str:
    content = read_text("/proc/cpuinfo") or ""
    fallback = None
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key.lower() in {"model name", "hardware", "cpu model"} and value:
            return value
        if key.lower() == "processor" and value and fallback is None:
            fallback = value
    return fallback or safe_call(platform.processor) or UNKNOWN


def mounts() -> list[tuple[str, str, str, str]]:
    result = []
    content = read_text("/proc/mounts") or ""
    for line in content.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            result.append((fields[0], fields[1], fields[2], fields[3]))
    return result


def cgroup_info() -> tuple[str, Path | None, dict[str, Path], str]:
    unified: Path | None = None
    controllers: dict[str, Path] = {}
    for _, mount_point, fs_type, options in mounts():
        if fs_type == "cgroup2":
            unified = Path(mount_point)
        elif fs_type == "cgroup":
            for option in options.split(","):
                if option in {"cpu", "cpuacct", "cpuset", "memory", "pids", "blkio", "io", "devices"}:
                    controllers.setdefault(option, Path(mount_point))
    content = read_text("/proc/self/cgroup") or ""
    relative = "/"
    for line in content.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[2]:
            relative = fields[2]
            break
    version = "v2" if unified else ("v1" if controllers else UNKNOWN)
    return version, unified, controllers, relative


def cgroup_read(names: tuple[str, ...], unified: Path | None, controllers: dict[str, Path], relative: str) -> str | None:
    for name in names:
        if unified:
            value = first_line(unified / relative.lstrip("/") / name)
            if value:
                return value
        for mount in controllers.values():
            value = first_line(mount / relative.lstrip("/") / name)
            if value:
                return value
    return None


def cpu_allocation(unified: Path | None, controllers: dict[str, Path], relative: str) -> dict[str, Any]:
    result: dict[str, Any] = {"quota": None, "period": None, "vcpu": None, "weight": None}
    if unified:
        raw = cgroup_read(("cpu.max",), unified, controllers, relative)
        if raw:
            fields = raw.split()
            quota = fields[0] if fields else None
            period = parse_int(fields[1]) if len(fields) > 1 else None
            result.update(quota=quota, period=period)
            quota_number = parse_int(quota) if quota not in {None, "max"} else None
            if quota_number is not None and quota_number >= 0 and period and period > 0:
                result["vcpu"] = quota_number / period
        result["weight"] = cgroup_read(("cpu.weight",), unified, controllers, relative)
    else:
        quota = cgroup_read(("cpu.cfs_quota_us",), unified, controllers, relative)
        period = cgroup_read(("cpu.cfs_period_us",), unified, controllers, relative)
        result.update(quota=quota, period=parse_int(period))
        quota_number = parse_int(quota)
        period_number = parse_int(period)
        if quota_number is not None and quota_number >= 0 and period_number and period_number > 0:
            result["vcpu"] = quota_number / period_number
        result["weight"] = cgroup_read(("cpu.shares",), unified, controllers, relative)
    return result


def detect_container(version: str, unified: Path | None) -> str:
    evidence: list[str] = []
    if Path("/.dockerenv").is_file():
        evidence.append("/.dockerenv")
    if Path("/run/.containerenv").is_file():
        evidence.append("/run/.containerenv")
    marker = (read_text("/proc/1/cgroup") or "").lower()
    if any(token in marker for token in ("docker", "containerd", "kubepods", "libpod", "lxc")):
        evidence.append("container marker")
    if evidence:
        return "Yes"
    if version in {"v1", "v2"} and unified is not None:
        return "Unknown / conflicting evidence"
    if marker and marker.strip() in {"0::/", "0::/init.scope"}:
        return "No"
    return UNKNOWN


def detect_platform() -> str:
    env = os.environ
    if env.get("RENDER", "").lower() == "true" or any(env.get(k) for k in ("RENDER_SERVICE_NAME", "RENDER_SERVICE_ID")):
        return "Render"
    if env.get("K_SERVICE") or env.get("K_REVISION"):
        return "Google Cloud Run"
    if env.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "AWS Lambda"
    if env.get("DYNO") or env.get("HEROKU_APP_NAME"):
        return "Heroku"
    if env.get("VERCEL"):
        return "Vercel"
    if env.get("RAILWAY_ENVIRONMENT"):
        return "Railway"
    if env.get("FLY_APP_NAME"):
        return "Fly.io"
    if env.get("GITHUB_ACTIONS"):
        return "GitHub Actions"
    if env.get("CODEBUILD_BUILD_ARN"):
        return "AWS CodeBuild"
    return "Unknown"


def root_filesystem() -> dict[str, Any]:
    result: dict[str, Any] = {"total": None, "used": None, "free": None, "type": UNKNOWN, "mount": UNKNOWN}
    try:
        usage = shutil.disk_usage("/")
        result.update(total=usage.total, used=usage.used, free=usage.free)
    except (OSError, ValueError):
        pass
    for source, mount, fs_type, _ in mounts():
        if mount == "/":
            result.update(type=fs_type or UNKNOWN, mount=f"{source} on {mount}")
            break
    return result


def process_limits() -> dict[str, str]:
    result = {"open_files": UNKNOWN, "processes": UNKNOWN}
    content = read_text("/proc/self/limits") or ""
    for line in content.splitlines():
        fields = line.split()
        if line.startswith("Max open files") and len(fields) >= 4:
            result["open_files"] = f"{fields[3]} soft / {fields[4] if len(fields) > 4 else UNKNOWN} hard"
        elif line.startswith("Max processes") and len(fields) >= 4:
            result["processes"] = f"{fields[2]} soft / {fields[3] if len(fields) > 3 else UNKNOWN} hard"
    return result


def network_interfaces() -> list[str]:
    result = []
    try:
        names = sorted(name for _, name in socket.if_nameindex())
    except (OSError, AttributeError):
        try:
            names = sorted(os.listdir("/sys/class/net"))
        except OSError:
            names = []
    for name in names:
        address = first_line(f"/sys/class/net/{name}/address") or UNKNOWN
        state = first_line(f"/sys/class/net/{name}/operstate") or UNKNOWN
        result.append(f"{name} (state={state}, MAC={address})")
    return result


def safe_environment() -> list[str]:
    result = []
    try:
        items = os.environ.items()
    except Exception:
        return result
    for name, value in sorted(items):
        if name not in SAFE_ENVIRONMENT_NAMES or SECRET_NAME_RE.search(name):
            continue
        safe_value = value[:197] + "..." if len(value) > 200 else value
        result.append(f"{name}={safe_value}")
    return result


def section(title: str) -> None:
    print(f"\n{'=' * 16} {title} {'=' * 16}")


def item(label: str, value: Any) -> None:
    if value is None or value == "":
        value = UNKNOWN
    print(f"{label:<34} {value}")


def collect_system() -> None:
    section("SYSTEM")
    item("OS", safe_call(platform.system))
    values = read_kv_file("/etc/os-release")
    item("Linux distribution", values.get("PRETTY_NAME") or values.get("NAME") or UNKNOWN)
    item("Kernel version", safe_call(platform.release))
    item("Architecture", safe_call(platform.architecture()[0]))
    item("Machine", safe_call(platform.machine))
    item("Hostname", safe_call(socket.gethostname))
    item("Uptime", safe_call(format_uptime))


def collect_cpu(cgroup: tuple[str, Path | None, dict[str, Path], str]) -> None:
    section("CPU")
    version, unified, controllers, relative = cgroup
    allocation = safe_call(lambda: cpu_allocation(unified, controllers, relative), {})
    item("CPU model", safe_call(cpu_model))
    item("Visible logical CPUs", safe_call(os.cpu_count))
    item("CPU architecture", safe_call(platform.machine))
    quota = allocation.get("quota") if isinstance(allocation, dict) else None
    period = allocation.get("period") if isinstance(allocation, dict) else None
    item("CPU quota", UNLIMITED if quota == "max" or quota == "-1" else (f"{quota} µs" if quota is not None else UNKNOWN))
    item("CPU period", f"{period} µs" if period else UNKNOWN)
    vcpu = allocation.get("vcpu") if isinstance(allocation, dict) else None
    item("Allocated CPU", f"{vcpu:.2f} vCPU" if isinstance(vcpu, float) else (UNLIMITED if quota in {"max", "-1"} else UNKNOWN))
    item("CPU weight / shares", allocation.get("weight") if isinstance(allocation, dict) else UNKNOWN)
    provider_cpu = os.environ.get("RENDER_CPU_COUNT")
    item("Provider-reported CPU allocation", f"{provider_cpu} vCPU (Render)" if provider_cpu else UNKNOWN)


def collect_memory(cgroup: tuple[str, Path | None, dict[str, Path], str]) -> None:
    section("MEMORY")
    _, unified, controllers, relative = cgroup
    mem = safe_call(parse_meminfo, {})
    total = mem.get("MemTotal")
    available = mem.get("MemAvailable")
    item("Host-visible memory", format_bytes(total))
    item("Available memory", format_bytes(available))
    item("Used visible memory", format_bytes(total - available if total is not None and available is not None else None))
    item("Memory allocation / limit", format_limit(cgroup_read(("memory.max", "memory.limit_in_bytes"), unified, controllers, relative)))
    item("cgroup memory current", format_bytes(parse_limit(cgroup_read(("memory.current", "memory.usage_in_bytes"), unified, controllers, relative))))
    item("cgroup memory high", format_limit(cgroup_read(("memory.high",), unified, controllers, relative)))
    item("cgroup memory swap limit", format_limit(cgroup_read(("memory.swap.max", "memory.memsw.limit_in_bytes"), unified, controllers, relative)))
    item("Swap total", format_bytes(mem.get("SwapTotal")))
    item("Swap free", format_bytes(mem.get("SwapFree")))


def collect_storage() -> None:
    section("STORAGE")
    fs = safe_call(root_filesystem, {})
    item("Visible root filesystem total", format_bytes(fs.get("total")))
    item("Visible root filesystem used", format_bytes(fs.get("used")))
    item("Visible root filesystem free", format_bytes(fs.get("free")))
    item("Filesystem type", fs.get("type", UNKNOWN))
    item("Mount information", fs.get("mount", UNKNOWN))
    writable = safe_call(lambda: os.access("/", os.W_OK), None)
    item("Root filesystem writable", "Yes" if writable is True else "No" if writable is False else UNKNOWN)
    item("Provider-reported disk allocation", UNKNOWN)


def collect_container(cgroup: tuple[str, Path | None, dict[str, Path], str]) -> None:
    section("CONTAINER / CGROUP")
    version, unified, controllers, relative = cgroup
    item("Container detected", safe_call(lambda: detect_container(version, unified)))
    item("cgroup version", version)
    item("cgroup path", relative)
    item("PID limit", format_limit(cgroup_read(("pids.max",), unified, controllers, relative)))
    item("PID current", cgroup_read(("pids.current",), unified, controllers, relative) or UNKNOWN)
    item("I/O limit information", cgroup_read(("io.max", "blkio.throttle.read_bps_device"), unified, controllers, relative) or UNKNOWN)


def collect_process() -> None:
    section("PROCESS")
    item("Current PID", safe_call(os.getpid))
    item("Parent PID", safe_call(os.getppid))
    item("Effective UID", safe_call(os.geteuid) if hasattr(os, "geteuid") else UNKNOWN)
    item("Effective GID", safe_call(os.getegid) if hasattr(os, "getegid") else UNKNOWN)
    item("Username", safe_call(getpass.getuser))
    limits = safe_call(process_limits, {})
    item("Open-file limits", limits.get("open_files", UNKNOWN))
    item("Process/PID limits", limits.get("processes", UNKNOWN))
    item("Process status", first_line("/proc/self/status") or UNKNOWN)


def collect_network() -> None:
    section("NETWORK")
    item("Hostname", safe_call(socket.gethostname))
    interfaces = safe_call(network_interfaces, [])
    item("Interfaces", "; ".join(interfaces) if interfaces else UNKNOWN)
    item("IPv4/IPv6 addresses", "Not queried; no network requests performed")


def collect_runtime() -> None:
    section("RUNTIME")
    item("Python version", safe_call(platform.python_version))
    item("Python implementation", safe_call(platform.python_implementation))
    item("Python executable", safe_call(sys.executable))
    item("Python architecture", safe_call(platform.architecture()[0]))
    item("Current working directory", safe_call(os.getcwd))
    item("Python prefix", safe_call(lambda: sys.prefix))
    item("Virtual environment", "Yes" if safe_call(lambda: sys.prefix != sys.base_prefix, False) else "No")


def collect_resource_allocation(cgroup: tuple[str, Path | None, dict[str, Path], str]) -> None:
    section("RESOURCE ALLOCATION")
    version, unified, controllers, relative = cgroup
    allocation = safe_call(lambda: cpu_allocation(unified, controllers, relative), {})
    vcpu = allocation.get("vcpu") if isinstance(allocation, dict) else None
    item("Allocated CPU", f"{vcpu:.2f} vCPU" if isinstance(vcpu, float) else (UNLIMITED if allocation.get("quota") in {"max", "-1"} else UNKNOWN))
    item("Memory allocation / limit", format_limit(cgroup_read(("memory.max", "memory.limit_in_bytes"), unified, controllers, relative)))
    item("PID allocation / limit", format_limit(cgroup_read(("pids.max",), unified, controllers, relative)))
    item("Allocation source", f"cgroup {version}" if version in {"v1", "v2"} else UNKNOWN)


def collect_platform() -> None:
    section("PLATFORM")
    item("Detected platform", safe_call(detect_platform))
    item("Provider-specific evidence", "Explicit runtime environment variables only; no hostname or hardware guessing")


def collect_environment() -> None:
    section("SAFE ENVIRONMENT")
    values = safe_call(safe_environment, [])
    if values:
        for value in values:
            print(f"  {value}")
    else:
        print(f"  {UNKNOWN}")
    print("  Secret-like and non-allowlisted environment variables are intentionally omitted.")


def run_collector(name: str, collector: Callable[[], None]) -> None:
    try:
        collector()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # Keep deployment logs clean: a failed optional section is represented
        # by a compact notice, never an exception traceback.
        section(name)
        item("Collector status", UNKNOWN)


def build_inspection_report() -> str:
    """Run the inspection once and return the complete report for stdout and HTTP."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        print("SYSTEM CONFIGURATION INSPECTOR")
        print("Read-only inspection using Python standard library; no external network calls.")
        if safe_call(platform.system) != "Linux":
            print("Platform notice: Linux-specific files may be unavailable; collecting portable values where possible.")
        cgroup = safe_call(cgroup_info, (UNKNOWN, None, {}, "/"))
        collectors = (
            ("SYSTEM", collect_system),
            ("CPU", lambda: collect_cpu(cgroup)),
            ("MEMORY", lambda: collect_memory(cgroup)),
            ("STORAGE", collect_storage),
            ("CONTAINER / CGROUP", lambda: collect_container(cgroup)),
            ("PROCESS", collect_process),
            ("NETWORK", collect_network),
            ("RUNTIME", collect_runtime),
            ("RESOURCE ALLOCATION", lambda: collect_resource_allocation(cgroup)),
            ("PLATFORM", collect_platform),
            ("SAFE ENVIRONMENT", collect_environment),
        )
        for name, collector in collectors:
            run_collector(name, collector)
    return output.getvalue()


class QuietReportHandler(http.server.BaseHTTPRequestHandler):
    """Serve the immutable startup report and a minimal health response."""

    report = ""

    def _send(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, self.report)
        elif path == "/healthz":
            self._send(200, "ok\n")
        else:
            self._send(404, "Not found\n")

    def do_HEAD(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        # Deployment logs should contain the startup report, not one line per request.
        return

    def do_POST(self) -> None:
        self._send(405, "Method not allowed\n")

    do_PUT = do_POST
    do_DELETE = do_POST


class InspectorHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def parse_port() -> int:
    raw = os.environ.get("PORT", "10000").strip()
    try:
        port = int(raw)
        if 1 <= port <= 65535:
            return port
    except (TypeError, ValueError):
        pass
    print(f"[system-config-inspector] Invalid PORT={raw!r}; using fallback port 10000.")
    return 10000


def serve_report(report: str, port: int) -> None:
    QuietReportHandler.report = report
    server = InspectorHTTPServer(("0.0.0.0", port), QuietReportHandler)
    stopping = {"value": False}

    def shutdown_handler(signum: int, _frame: Any) -> None:
        if not stopping["value"]:
            stopping["value"] = True
            print(f"\n[system-config-inspector] Shutdown signal {signum} received; stopping HTTP server.", flush=True)
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    print(f"[system-config-inspector] HTTP server listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        print("[system-config-inspector] HTTP server stopped.", flush=True)


def main() -> int:
    try:
        print("[system-config-inspector] Starting read-only runtime inspection...", flush=True)
        report = build_inspection_report()
        completed_report = report + "\n[system-config-inspector] Inspection completed successfully.\n"
        print(completed_report, end="", flush=True)
        serve_report(completed_report, parse_port())
        return 0
    except KeyboardInterrupt:
        print("\\n[system-config-inspector] Inspection interrupted; shutting down.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[system-config-inspector] Fatal application failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
