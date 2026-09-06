# System Configuration Inspector

A lightweight, read-only, dependency-free inspector for the Linux runtime and container configuration visible to a deployed process. It prints results directly to stdout so Docker and native Python deployment logs contain the inspection.

The project uses **Python standard library only** for the inspector and Bash only for `start.sh`. It has no API, HTTP server, frontend, database, runtime package installation, network calls, or telemetry.

## Architecture

`system_info.py` runs independent collectors for system identity, CPU, memory, storage, container/cgroup state, process limits, network visibility, Python runtime, resource allocation, provider detection, and a security-conscious environment allowlist. Each optional read is guarded. Missing files, unsupported cgroup controllers, malformed values, permission errors, and unavailable resources are represented as `Unknown / Not exposed` while the remaining sections continue.

`start.sh` prints a startup status, notes the presence of `PORT` without binding to it, and uses `exec` to run the inspector. The Docker image copies only the required files and exits normally after printing the report.

## Deployment

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

A platform-provided `PORT` variable is harmless. The program never starts a web server and never binds to a port.

### Docker-compatible platform

Use the included `Dockerfile` directly:

```bash
docker build -t system-config-inspector .
docker run --rm system-config-inspector
```

The container uses the official `python:3.12-slim` image, installs nothing, starts `start.sh`, prints the report, and exits.

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
| `NETWORK` | Hostname, locally visible interface state and MAC addresses; no network queries |
| `RUNTIME` | Python version, implementation, executable, architecture, prefix, virtual-environment status |
| `RESOURCE ALLOCATION` | cgroup-backed CPU, memory, and PID allocation/limits |
| `PLATFORM` | Provider only when explicit reliable environment evidence exists |
| `SAFE ENVIRONMENT` | Approved non-secret deployment metadata only |

## Visible hardware versus allocated resources

The report deliberately distinguishes resources visible to the process from resources allocated by a container or service. For example, visible logical CPUs are not treated as allocated CPUs. When cgroup quota and period are available, allocation is calculated as:

```text
allocated_vcpu = quota / period
```

For example, a quota of `15000` and period of `100000` is reported as `0.15 vCPU`. A missing, malformed, negative/unlimited quota, missing period, or zero period never causes division by zero; the result is reported as `Unknown / Not exposed` or `Unlimited / No enforced limit`.

Memory follows the same distinction. Host-visible memory is not called container RAM. The cgroup value is labeled `Memory allocation / limit`, formatted with human-readable units and raw bytes where available. Cgroup values such as `max` are reported as `Unlimited / No enforced limit` rather than converted into a fabricated number.

## cgroups and portability

Both cgroup v1 and v2 are supported when their mount and process paths are exposed. The inspector does not assume `/sys/fs/cgroup`, a particular mount path, a particular controller, Docker, Kubernetes, systemd, a Linux distribution, or root privileges. It checks available mount information and continues when individual controllers or files are missing.

The intended environments include Docker containers, Render Docker and native Python services, Kubernetes containers, generic Linux Python services, VPS systems, and local Linux installations. Windows is not required. If run on a non-Linux system, the program prints a platform notice and still collects portable Python-standard-library values where possible.

## Platform detection

Provider detection is conservative and uses explicit runtime environment variables only. It does not infer a provider from a hostname, IP address, CPU vendor, kernel, filesystem, or a generic Kubernetes/container signal. When reliable evidence is absent, the result is `Detected platform: Unknown`.

## Environment-variable security

The program never dumps the entire environment. It uses a small allowlist for values such as `PORT`, documented Render metadata, selected AWS/Cloud Run/Heroku/Vercel/Railway/Fly.io/GitHub Actions indicators, and `CI`. Secret-like names and credential-bearing variables—including passwords, tokens, API keys, auth values, private keys, database URLs, connection strings, JWTs, cookies, sessions, certificates, and SSH values—are excluded. Values are bounded in length, and no external URLs are queried.

## Output and failure behavior

Every section is attempted independently. Optional failures do not produce Python tracebacks in normal output. Unavailable fields are shown as `Unknown / Not exposed`, and a successful overall run ends with:

```text
[system-config-inspector] Inspection completed successfully.
```

The process returns a non-zero status only for an interruption or genuine unrecoverable application-level failure.

## Limitations

The inspector can only report what the runtime exposes. A container may not see the physical host's complete hardware configuration, and a root filesystem is not automatically a provider's persistent disk allocation. Cgroup values describe limits visible to the process, not necessarily the provider's internal billing or hardware model. Interface addresses are intentionally not queried through network APIs, and unavailable platform-specific information remains unknown rather than guessed.

## Validation

The recommended local checks are:

```bash
python3 -m py_compile system_info.py
bash -n start.sh
python3 system_info.py
PORT=8080 ./start.sh
```

If Docker is installed:

```bash
docker build -t system-config-inspector .
docker run --rm system-config-inspector
```
