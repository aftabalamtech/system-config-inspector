#!/usr/bin/env python3
"""Portable, dependency-free Linux runtime and container configuration inspector."""

from __future__ import annotations

import getpass
import os
import platform
import re
import shutil
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Any, Iterable

UNKNOWN = "Unknown / Not exposed"
SECRET_NAME_RE = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|API[_-]?KEY|ACCESS[_-]?KEY|AUTH|COOKIE|CERT|SSH|WEBHOOK)",
    re.IGNORECASE,
)
PLATFORM_ENV_NAMES = (
    "AWS_EXECUTION_ENV", "AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME",
    "CLOUD_RUN_JOB", "K_SERVICE", "K_REVISION", "DYNO", "RENDER",
    "VERCEL", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME", "HEROKU_APP_NAME",
    "NETLIFY", "GITHUB_ACTIONS", "CI", "CODEBUILD_BUILD_ARN",
)


def read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, UnicodeError):
        return None


def first_line(path: str | Path) -> str | None:
    value = read_text(path)
    return value.splitlines()[0].strip() if value else None


def display(value: Any) -> str:
    if value is None or value == "" or value == UNKNOWN:
        return UNKNOWN
    return str(value)


def format_bytes(value: int | float | None) -> str:
    if value is None or value < 0:
        return UNKNOWN
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    number = float(value)
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    return f"{number:.1f} {units[index]} ({int(value):,} bytes)"


def parse_bytes(value: str | None) -> int | None:
    if not value or value.lower() in {"max", "unlimited", "none"}:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def read_key_value_file(path: str | Path) -> dict[str, str]:
    result: dict[str, str] = {}
    content = read_text(path)
    if not content:
        return result
    for line in content.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def detect_distribution() -> str:
    values = read_key_value_file("/etc/os-release")
    name = values.get("PRETTY_NAME") or values.get("NAME")
    return name.strip('\\\"') if name else UNKNOWN


def uptime() -> str:
    raw = first_line("/proc/uptime")
    if not raw:
        return UNKNOWN
    try:
        seconds = int(float(raw.split()[0]))
    except (ValueError, IndexError):
        return UNKNOWN
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def cpu_model() -> str:
    content = read_text("/proc/cpuinfo")
    if content:
        preferred = {"model name", "hardware", "cpu model"}
        fallback = {"processor"}
        fallback_value = None
        for line in content.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.lower().strip()
            value = value.strip()
            if key in preferred and value:
                return value
            if key in fallback and value and fallback_value is None:
                fallback_value = value
        if fallback_value:
            return fallback_value
    return platform.processor() or UNKNOWN


def cgroup_version() -> str:
    mounts = read_text("/proc/mounts") or ""
    if any(" - cgroup2 " in line or " cgroup2 " in line for line in mounts.splitlines()):
        return "v2"
    if any(" - cgroup " in line or " cgroup " in line for line in mounts.splitlines()):
        return "v1"
    return UNKNOWN


def cgroup_mounts() -> tuple[Path | None, dict[str, Path]]:
    mounts = read_text("/proc/mounts") or ""
    unified: Path | None = None
    controllers: dict[str, Path] = {}
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mount_point, fs_type, options = parts[1], parts[2], parts[3]
        if fs_type == "cgroup2":
            unified = Path(mount_point)
        elif fs_type == "cgroup":
            for controller in options.split(","):
                if controller in {"cpu", "cpuacct", "cpuset", "memory", "pids", "blkio", "devices"}:
                    controllers.setdefault(controller, Path(mount_point))
    return unified, controllers


def cgroup_path(mount: Path, relative: str) -> Path:
    return mount / relative.lstrip("/")


def current_cgroup_relative_path() -> str:
    content = read_text("/proc/self/cgroup") or ""
    for line in content.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[2]:
            return parts[2]
    return "/"


def cgroup_value(names: Iterable[str], unified: Path | None, controllers: dict[str, Path]) -> str:
    relative = current_cgroup_relative_path()
    for name in names:
        if unified:
            value = first_line(cgroup_path(unified, relative) / name)
            if value:
                return value
        for controller, mount in controllers.items():
            value = first_line(cgroup_path(mount, relative) / name)
            if value:
                return value
    return UNKNOWN


def memory_limit(unified: Path | None, controllers: dict[str, Path]) -> int | None:
    raw = cgroup_value(("memory.max", "memory.limit_in_bytes"), unified, controllers)
    return parse_bytes(raw)


def memory_current(unified: Path | None, controllers: dict[str, Path]) -> int | None:
    raw = cgroup_value(("memory.current", "memory.usage_in_bytes"), unified, controllers)
    return parse_bytes(raw)


def cpu_limits(unified: Path | None, controllers: dict[str, Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    if unified:
        cpu_max = cgroup_value(("cpu.max",), unified, controllers)
        if cpu_max != UNKNOWN:
            values = cpu_max.split()
            if values and values[0] != "max":
                result["quota"] = f"{values[0]} µs per {values[1] if len(values) > 1 else UNKNOWN} µs period"
            else:
                result["quota"] = "Unlimited / Not configured"
        result["weight"] = cgroup_value(("cpu.weight",), unified, controllers)
    else:
        quota = cgroup_value(("cpu.cfs_quota_us",), unified, controllers)
        period = cgroup_value(("cpu.cfs_period_us",), unified, controllers)
        result["quota"] = UNKNOWN if quota == UNKNOWN else f"{quota} µs per {period} µs period"
        result["shares"] = cgroup_value(("cpu.shares",), unified, controllers)
    return result


def container_detection() -> str:
    evidence: list[str] = []
    if read_text("/.dockerenv") is not None:
        evidence.append("/.dockerenv")
    if read_text("/run/.containerenv") is not None:
        evidence.append("/run/.containerenv")
    marker = (read_text("/proc/1/cgroup") or "").lower()
    if any(token in marker for token in ("docker", "containerd", "kubepods", "libpod", "lxc")):
        evidence.append("container marker in /proc/1/cgroup")
    if evidence:
        return "Likely yes (evidence: " + "; ".join(evidence) + ")"
    return "No reliable container evidence detected"


def safe_environment() -> list[str]:
    visible = []
    for key in sorted(os.environ):
        if key == "PATH" or SECRET_NAME_RE.search(key):
            continue
        if key.startswith("_"):
            continue
        value = os.environ[key]
        if len(value) > 200:
            value = value[:197] + "..."
        visible.append(f"{key}={value}")
    return visible


def platform_detection() -> str:
    detected: list[str] = []
    env = os.environ
    if env.get("K_SERVICE") or env.get("K_REVISION"):
        detected.append("Google Cloud Run")
    if env.get("AWS_LAMBDA_FUNCTION_NAME"):
        detected.append("AWS Lambda")
    if env.get("DYNO") or env.get("HEROKU_APP_NAME"):
        detected.append("Heroku")
    if env.get("VERCEL"):
        detected.append("Vercel")
    if env.get("RENDER"):
        detected.append("Render")
    if env.get("RAILWAY_ENVIRONMENT"):
        detected.append("Railway")
    if env.get("FLY_APP_NAME"):
        detected.append("Fly.io")
    if env.get("GITHUB_ACTIONS"):
        detected.append("GitHub Actions")
    if env.get("CODEBUILD_BUILD_ARN"):
        detected.append("AWS CodeBuild")
    return ", ".join(detected) if detected else UNKNOWN


def section(title: str) -> None:
    print(f"\n{'=' * 18} {title} {'=' * 18}")


def item(label: str, value: Any) -> None:
    print(f"{label:<32} {display(value)}")


def collect_and_print() -> None:
    unified, controllers = cgroup_mounts()
    section("SYSTEM")
    item("OS", platform.system() or UNKNOWN)
    item("Linux distribution", detect_distribution())
    item("Kernel version", platform.release() or UNKNOWN)
    item("Architecture", platform.architecture()[0])
    item("Machine", platform.machine())
    item("Hostname", socket.gethostname())
    item("Uptime", uptime())
    item("Detected platform", platform_detection())

    section("CPU")
    item("CPU model", cpu_model())
    item("Logical CPU count", os.cpu_count())
    item("CPU architecture", platform.machine())
    limits = cpu_limits(unified, controllers)
    item("CPU quota / limit", limits.get("quota"))
    item("CPU shares / weight", limits.get("shares") or limits.get("weight"))

    section("MEMORY")
    meminfo: dict[str, str] = {}
    meminfo_text = read_text("/proc/meminfo") or ""
    for line in meminfo_text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meminfo[key.strip()] = value.strip()
    total = int(meminfo["MemTotal"].split()[0]) * 1024 if "MemTotal" in meminfo else None
    available = int(meminfo["MemAvailable"].split()[0]) * 1024 if "MemAvailable" in meminfo else None
    item("Total visible memory", format_bytes(total))
    item("Available memory", format_bytes(available))
    item("Used memory", format_bytes(total - available if total is not None and available is not None else None))
    item("cgroup memory limit", format_bytes(memory_limit(unified, controllers)))
    item("cgroup memory current", format_bytes(memory_current(unified, controllers)))
    item("Swap total", format_bytes(int(meminfo["SwapTotal"].split()[0]) * 1024 if "SwapTotal" in meminfo else None))
    item("Swap free", format_bytes(int(meminfo["SwapFree"].split()[0]) * 1024 if "SwapFree" in meminfo else None))

    section("STORAGE")
    usage = shutil.disk_usage("/")
    item("Root filesystem total", format_bytes(usage.total))
    item("Root filesystem used", format_bytes(usage.used))
    item("Root filesystem free", format_bytes(usage.free))
    filesystem = UNKNOWN
    mounts = read_text("/proc/mounts") or ""
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "/":
            filesystem = parts[2]
            break
    item("Filesystem type", filesystem)

    section("CONTAINER / CGROUP")
    item("Container detected", container_detection())
    item("cgroup version", cgroup_version())
    item("cgroup path", current_cgroup_relative_path())
    item("PID limit", cgroup_value(("pids.max",), unified, controllers))
    item("PID current", cgroup_value(("pids.current",), unified, controllers))
    item("I/O limit information", cgroup_value(("io.max", "blkio.throttle.read_bps_device"), unified, controllers))

    section("PROCESS")
    item("Current PID", os.getpid())
    item("Parent PID", os.getppid())
    item("User", getpass.getuser())
    item("UID / GID", f"{os.getuid()} / {os.getgid()}" if hasattr(os, "getuid") else UNKNOWN)
    limits_file = read_text("/proc/self/limits")
    open_files = UNKNOWN
    max_processes = UNKNOWN
    if limits_file:
        for line in limits_file.splitlines():
            if line.startswith("Max open files"):
                open_files = " ".join(line.split()[3:])
            elif line.startswith("Max processes"):
                max_processes = " ".join(line.split()[2:])
    item("Open-file limit", open_files)
    item("Process limit", max_processes)

    section("NETWORK")
    item("Hostname", socket.gethostname())
    interfaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            address = first_line(f"/sys/class/net/{name}/address") or UNKNOWN
            state = first_line(f"/sys/class/net/{name}/operstate") or UNKNOWN
            interfaces.append(f"{name} (state={state}, MAC={address})")
    except OSError:
        pass
    item("Interfaces", "; ".join(interfaces) if interfaces else UNKNOWN)
    item("Hostname resolution", socket.getfqdn())

    section("RUNTIME")
    item("Python version", platform.python_version())
    item("Python executable", sys.executable)
    item("Python implementation", platform.python_implementation())
    item("Current working directory", os.getcwd())

    section("SAFE ENVIRONMENT")
    item("PORT", os.environ.get("PORT", UNKNOWN))
    for name in PLATFORM_ENV_NAMES:
        if name in os.environ and name != "PORT":
            item(name, os.environ[name])
    print("Non-secret environment variables")
    for value in safe_environment():
        print(f"  {value}")
    print("\nSecret-like environment variable names and values are intentionally omitted.")


def main() -> int:
    try:
        print("SYSTEM CONFIGURATION INSPECTOR")
        print("Read-only, standard-library inspection; values reflect the current runtime/container.")
        collect_and_print()
        return 0
    except KeyboardInterrupt:
        print("\nInspection interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Fatal inspection error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
