# System Configuration Inspector

A lightweight, read-only Python utility that prints the runtime and container configuration visible to the current Linux environment. It is designed for deployment platforms where stdout appears in build or runtime logs.

The project has **no API, web server, dashboard, frontend, database, framework, or third-party Python dependency**. It uses Python's standard library and Linux files such as `/proc`, `/sys`, and cgroup files.

## What it detects

The inspector reports, when exposed by the runtime:

- System identity: operating system, distribution, kernel, architecture, machine, hostname, uptime, and reliable platform indicators.
- CPU: model, logical CPU count, architecture, and cgroup quota, period, shares, or weight.
- Memory: visible total, available and used memory, swap, and cgroup memory limit/current usage.
- Storage: root filesystem capacity, used/free space, and detectable filesystem type.
- Container and cgroup state: container evidence, cgroup version/path, memory, CPU, PID, and I/O limits.
- Process details: PIDs, user and group IDs, open-file limit, and process limit.
- Network visibility: hostname and interfaces with operational state and MAC address where readable.
- Runtime: Python version, executable, implementation, and working directory.
- Safe environment configuration: `PORT` and non-secret runtime/platform indicators.

Secret-like environment variables—including names containing `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `PRIVATE_KEY`, `API_KEY`, `AUTH`, or `COOKIE`—are intentionally omitted. Long values are truncated. The utility does not make network requests.

## Docker deployment

Build and run the image:

```bash
docker build -t system-config-inspector .
docker run --rm system-config-inspector
```

The container runs the inspector automatically through `start.sh` and exits with the inspector's exit code. If `PORT` is supplied by a deployment platform, it is reported but never used to start a listener.

## Native Python deployment

This project needs only a standard Linux Python runtime and has no dependency installation step.

Recommended build command:

```text
No build command required
```

Recommended start command:

```bash
python system_info.py
```

Alternatively, use the startup script:

```bash
./start.sh
```

The startup script requires Bash and safely forwards the Python process exit code.

## Example output

A typical run includes sections like the following. Exact values depend on the deployment runtime:

```text
================== SYSTEM ==================
OS                              Linux
Linux distribution              Debian GNU/Linux 12 (bookworm)
Kernel version                  6.x.x
Architecture                    64bit
Machine                         x86_64
Hostname                        runtime-instance
Uptime                          2h 14m 09s
Detected platform               Unknown / Not exposed

================== CPU ==================
CPU model                       AMD EPYC ...
Logical CPU count               2
CPU architecture                x86_64
CPU quota / limit               200000 µs per 100000 µs period
CPU shares / weight             100
```

Unavailable or permission-restricted values are printed as `Unknown / Not exposed`; the inspector does not fabricate values. Individual missing Linux files, unsupported cgroup fields, and permission errors do not prevent other checks from running.

## Interpretation and limitations

A container generally sees the resources and kernel interfaces exposed to it, not necessarily the complete physical host configuration. CPU, memory, PID, and other cgroup values describe the limits visible to the container or runtime. Filesystem capacity describes the mounted root filesystem available from inside the environment.

Container detection and deployment-platform detection are deliberately conservative. A provider is reported only when reliable environment variables or runtime evidence are present; otherwise the result is `Unknown / Not exposed`. Network information is similarly limited to what the runtime exposes locally.

## Validation

The project can be checked without third-party packages:

```bash
python3 -m py_compile system_info.py
bash -n start.sh
python3 system_info.py
```
