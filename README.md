# System Configuration Inspector

A lightweight, read-only, dependency-free runtime and container configuration inspector designed to run as a long-lived Render Web Service or as a Docker/native Python application. It collects the visible Linux runtime configuration once at startup, prints the complete report to stdout, and serves that same immutable report through a minimal Python standard-library HTTP viewer.

The project uses **Python standard library only** for both inspection and HTTP serving, with Bash only for `start.sh`. It has no framework, database, frontend, package installation, external network calls, telemetry, or command execution from requests.

## Architecture

`system_info.py` runs independent collectors for system identity, CPU, memory, storage, container/cgroup state, process limits, network visibility, Python runtime, resource allocation, provider detection, and a security-conscious environment allowlist. Each optional read is guarded. Missing files, unsupported cgroup controllers, malformed values, permission errors, and unavailable resources are represented as `Unknown / Not exposed` while the remaining sections continue.

After the one-time inspection completes, the process starts a minimal `http.server`/`socketserver` listener on `0.0.0.0:$PORT`. The report is stored in memory and is not recomputed per request. The service remains alive in the foreground for Render Web Service health checks.

`start.sh` prints a startup status and executes the Python process. It does not terminate while the server is running and does not start a second server.

## HTTP endpoints

| Method | Path | Response |
|---|---|---|
| `GET` | `/` | HTTP 200 with the complete plain-text startup report. |
| `GET` | `/healthz` | HTTP 200 with `ok`. |
| `HEAD` | `/`, `/healthz` | Optional header-only equivalent. |
| Other | Any other path | HTTP 404. |

`POST`, `PUT`, and `DELETE` are not supported and return HTTP 405. Directory listing is not enabled. Responses include UTF-8 `Content-Type`, `Content-Length`, and `Cache-Control: no-store`. Broken client connections are ignored safely, and per-request access logs are suppressed.

The server binds specifically to `0.0.0.0`. It reads `PORT` from the environment and uses `10000` only when `PORT` is absent or invalid. It never binds to localhost and never derives a production port from a hardcoded service configuration.

## Deployment

### Render Web Service

Use the repository as a Render Web Service. The service must use the following start command, or the equivalent script:

```bash
python system_info.py
```

The application reads Render's `PORT`, prints the complete inspection report, logs the listener address, and remains running. A typical startup sequence is:

```text
[system-config-inspector] Starting read-only runtime inspection...
...
[system-config-inspector] Inspection completed successfully.
[system-config-inspector] HTTP server listening on 0.0.0.0:10000
```

The `PORT` value may differ in a deployed environment.

### Native Python platform

No build command is required because there are no dependencies:

```text
No build command required
```

Recommended start command:

```bash
python system_info.py
```

If Bash is available, this is also supported:

```bash
./start.sh
```

### Docker-compatible platform

Use the included `Dockerfile` directly:

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

The image uses the official `python:3.12-slim` base, installs nothing, starts `start.sh`, exposes the listener through the supplied `PORT`, and remains alive until it receives `SIGTERM` or `SIGINT`.

## Reported information

The report contains the following plain-log sections:

| Section | Examples of reported information |
|---|---|
| `SYSTEM` | OS, distribution, kernel, architecture, machine, hostname, uptime |
| `CPU` | CPU model, visible logical CPUs, quota, period, calculated vCPU allocation, weight/shares |
| `MEMORY` | Host-visible memory, available/used memory, cgroup limit/current/high/swap limits, swap |
| `STORAGE` | Visible root filesystem capacity, filesystem type, mount, writable status |
| `CONTAINER / CGROUP` | Conservative container result, cgroup version/path, PID and I/O limits |
| `PROCESS` | PIDs, effective UID/GID, username, open-file and process limits |
| `NETWORK` | Hostname and locally visible interface state/MAC addresses; no network queries |
| `RUNTIME` | Python version, implementation, executable, architecture, prefix, virtual-environment status |
| `RESOURCE ALLOCATION` | cgroup-backed CPU, memory, and PID allocation/limits |
| `PLATFORM` | Provider only when explicit reliable environment evidence exists |
| `SAFE ENVIRONMENT` | Approved non-secret deployment metadata only |

## Visible hardware versus allocated resources

The report deliberately distinguishes resources visible to the process from resources allocated by a container or service. Visible logical CPUs are not treated as allocated CPUs. When cgroup quota and period are available, allocation is calculated as:

```text
allocated_vcpu = quota / period
```

For example, a quota of `15000` and period of `100000` is reported as `0.15 vCPU`. A missing, malformed, negative/unlimited quota, missing period, or zero period never causes division by zero; the result is reported as `Unknown / Not exposed` or `Unlimited / No enforced limit`.

Memory follows the same distinction. Host-visible memory is not called container RAM. The cgroup value is labeled `Memory allocation / limit`, formatted with human-readable units and raw bytes where available. Cgroup values such as `max` are reported as `Unlimited / No enforced limit` rather than converted into a fabricated number. Visible root filesystem capacity is not labeled as provider persistent disk allocation.

## cgroups and portability

Both cgroup v1 and v2 are supported when their mount and process paths are exposed. The inspector does not assume `/sys/fs/cgroup`, a particular mount path, a particular controller, Docker, Kubernetes, systemd, a Linux distribution, or root privileges. It checks available mount information and continues when individual controllers or files are missing.

The intended environments include Docker containers, Render Docker and native Python services, Kubernetes containers, generic Linux Python services, VPS systems, and local Linux installations. Windows is not required. If run on a non-Linux system, the program prints a platform notice and still collects portable Python-standard-library values where possible.

## Platform detection

Provider detection is conservative and uses explicit runtime environment variables only. It does not infer a provider from a hostname, IP address, CPU vendor, kernel, filesystem, or a generic Kubernetes/container signal. When reliable evidence is absent, the result is `Detected platform: Unknown`.

## Environment-variable security

The program never dumps the entire environment. It uses a small allowlist for values such as `PORT`, documented Render metadata, selected AWS/Cloud Run/Heroku/Vercel/Railway/Fly.io/GitHub Actions indicators, and `CI`. Secret-like names and credential-bearing variables—including passwords, tokens, API keys, auth values, private keys, database URLs, connection strings, JWTs, cookies, sessions, certificates, and SSH values—are excluded. Values are bounded in length, and HTTP requests cannot execute commands, modify files, or modify the environment.

## Graceful shutdown

The foreground server handles `SIGTERM` and `SIGINT`, prints a concise shutdown message, stops accepting requests, closes the HTTP server, and exits cleanly. The server uses daemon request threads so an interrupted client cannot prevent shutdown.

## Validation

Run the following local checks:

```bash
python3 -m py_compile system_info.py
bash -n start.sh
PORT=10000 python system_info.py
```

With the process running in another terminal:

```bash
curl -i http://127.0.0.1:10000/
curl -i http://127.0.0.1:10000/healthz
curl -i http://127.0.0.1:10000/unknown
```

If Docker is installed:

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

## Limitations

The inspector can only report what the runtime exposes. A container may not see the physical host's complete hardware configuration, and a root filesystem is not automatically a provider's persistent disk allocation. Cgroup values describe limits visible to the process, not necessarily the provider's internal billing or hardware model. Interface addresses are intentionally not queried through network APIs, and unavailable platform-specific information remains unknown rather than guessed.
