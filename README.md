# Universal Linux Environment Inspector

A lightweight, read-only, dependency-free inspector for the Linux runtime and container configuration visible to a deployed process. It is designed for Docker, Docker Compose, Kubernetes, ECS/Fargate, EC2, Render, Railway, Fly.io, VPS, virtual machines, bare metal, and generic Linux hosting.

The project uses **Python standard library only** for inspection and HTTP serving, with Bash only for `start.sh`. It has no third-party packages, cloud SDKs, external network requests, telemetry, runtime installation, database, frontend, or command execution from HTTP requests.

## Architecture

`system_info.py` runs independent collectors for system identity, CPU/topology, memory, storage, cgroups, container evidence, namespaces, process state, local network configuration, Python runtime, resource allocation, process limits, virtualization, security/privileges, provider detection, and a strict safe environment allowlist. Every optional collector is isolated. Missing files, unsupported controllers, malformed values, permission errors, and unavailable resources are represented as `Unknown / Not exposed` while later sections continue.

The inspection runs once at startup. Its complete report is printed to stdout and stored in memory. A minimal Python standard-library HTTP server then serves the same immutable report from `GET /` and keeps the process alive for Render Web Service health checks.

## HTTP endpoints

| Method | Path | Response |
|---|---|---|
| `GET` | `/` | HTTP 200 with the complete plain-text startup report. |
| `GET` | `/healthz` | HTTP 200 with `ok`. |
| `HEAD` | `/`, `/healthz` | Header-only equivalent. |
| Other | Any other path | HTTP 404. |

`POST`, `PUT`, and `DELETE` return HTTP 405. Directory listing is not enabled. Responses include UTF-8 content type, content length, and `Cache-Control: no-store`. Request logs are suppressed, and broken client connections are handled quietly.

The server binds to `0.0.0.0`, reads `PORT`, and uses `10000` only if `PORT` is absent or invalid. It never binds to localhost and never performs a network request.

## Report sections

| Section | Information included |
|---|---|
| `SYSTEM` | OS, distribution/version, kernel release/build, architecture, hostname, uptime/boot time, timezone, locale, init/systemd, user, shell, virtualization hint |
| `CPU` | Model, vendor, visible/online/offline CPUs, architecture, topology, frequency, flags, affinity, cgroup quota/period/weight, cpuset, calculated vCPU, provider-reported allocation |
| `MEMORY` | Host-visible total/available/used/free memory, buffers, cached, swap, cgroup allocation/current/high/max/swap-max, pressure, memory events |
| `STORAGE` | Visible root filesystem capacity, mount/options, filesystem type, read-only/writable status, inode counts, filesystem list, visible block devices |
| `CONTAINER / CGROUP` | Conservative Yes/Unknown result, confidence/evidence, cgroup version/path, exposed controllers, PID count limits/current usage, I/O limits |
| `NAMESPACES` | PID, mount, network, IPC, UTS, user, and cgroup namespace identifiers where permitted |
| `PROCESS` | PID/PPID, process name/executable/command line, UID/GID, username/groups, thread count, status, open-file/process limits |
| `NETWORK` | Locally visible interfaces, state/MAC, route/default-route counts, DNS configuration metadata, `/etc/hosts` metadata; no DNS queries |
| `RUNTIME` | Python version/implementation/executable/architecture/compiler/build, prefixes, virtual-environment state, site packages, `sys.path` count |
| `RESOURCE ALLOCATION` | cgroup-backed CPU, memory, and PID allocation/limits, separately from process limits |
| `RESOURCE LIMITS` | Process-level open-file, process, stack, core, locked-memory, address-space, and file-size limits |
| `VIRTUALIZATION` | Conservative virtualization/container hint with confidence and evidence |
| `SECURITY` | Root status, effective capability mask, no-new-privileges, seccomp, AppArmor/SELinux presence, root filesystem access status |
| `PLATFORM` | Provider, confidence, and explicit environment-variable evidence |
| `SAFE ENVIRONMENT` | Approved non-secret deployment metadata only |

## Visible hardware versus allocated resources

Visible resources are never presented as allocated resources. For CPU, visible logical CPUs, CPU quota, CPU period, CPU weight/shares, effective CPU set, and calculated allocated vCPU are separate fields. When quota and period are valid, allocation is calculated as:

```text
allocated_vcpu = quota / period
```

For example, `15000 / 100000` is reported as `0.15 vCPU`. Missing, malformed, negative/unlimited, missing-period, or zero-period values never cause division by zero. They are reported as `Unknown / Not exposed` or `Unlimited / No enforced limit`.

For memory, `/proc/meminfo` is labeled **Host-visible memory**. Cgroup values are labeled **Memory allocation / limit**, current, high, max, or swap max. A cgroup value of `max` becomes `Unlimited / No enforced limit`, never a fabricated byte count. Visible root filesystem capacity is not labeled provider disk allocation.

PID limits are formatted as process counts, not byte units. Process-level `RLIMIT_*` values and cgroup-level limits are shown in separate sections.

## cgroups and portability

Both cgroup v1 and v2 are supported when mount and process paths are exposed. The inspector does not assume `/sys/fs/cgroup`, a particular mount path, a particular controller, Docker, Kubernetes, systemd, a Linux distribution, root privileges, or a CPU vendor. It discovers exposed controllers and continues when individual files are missing.

The application is intended for Linux x86_64 and ARM64 environments, cgroup v1/v2, minimal Linux systems, Kubernetes-style environments, ECS/Fargate-style environments, generic VPS/VMs, bare metal, and restricted `/proc` or `/sys` environments. Windows is not required; on non-Linux systems the program prints a platform notice and collects portable Python values where available.

## Container and provider detection

Container detection combines independent signals such as container marker files, PID/self cgroup markers, Kubernetes/ECS environment evidence, and cgroup context. It reports `Yes`, `Unknown`, or `Unknown / conflicting evidence` with confidence and evidence instead of relying on a single weak heuristic.

Provider detection requires explicit evidence. Recognized examples include Render, AWS ECS/Fargate, AWS ECS, AWS Lambda, Kubernetes, Cloud Run, Heroku, Vercel, Railway, and Fly.io. The inspector never infers a provider from hostname, IP, CPU model, kernel, filesystem, or Kubernetes-like strings alone.

## Security and environment filtering

The program never dumps `os.environ`. It uses a small allowlist for values such as `PORT`, Render metadata, selected AWS/ECS/Kubernetes indicators, Cloud Run, Heroku, Vercel, Railway, Fly.io, GitHub Actions, and `CI`. Secret-like names and credential-bearing values—including passwords, tokens, API keys, auth values, private keys, database URLs, connection strings, JWTs, cookies, sessions, certificates, and SSH values—are excluded and long values are bounded.

HTTP requests are read-only. They cannot execute commands, modify files, modify environment variables, or trigger a fresh inspection.

## Deployment

### Render Web Service

Use the repository as a Render Web Service with:

```text
Build Command: No build command required
Start Command: python system_info.py
```

The process reads Render's `PORT`, prints the report, logs the listener address, and remains alive. The health endpoint is `/healthz`.

### Native Python

```bash
python system_info.py
```

If Bash is available:

```bash
./start.sh
```

### Docker

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

The Dockerfile uses the official `python:3.12-slim` image, installs nothing, starts `start.sh`, and keeps the HTTP service in the foreground.

## Graceful shutdown and validation

`SIGTERM` and `SIGINT` are handled gracefully. The server prints a concise shutdown message, closes the listener, and exits cleanly.

Recommended checks:

```bash
python -m py_compile system_info.py
bash -n start.sh
PORT=10000 python system_info.py
curl -i http://127.0.0.1:10000/
curl -i http://127.0.0.1:10000/healthz
curl -i http://127.0.0.1:10000/unknown
```

If Docker is available:

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

## Limitations

The inspector reports only what the current runtime exposes. A container may not see the physical host's complete hardware configuration, and a visible root filesystem is not automatically a provider's persistent disk allocation. DMI, security, namespace, cgroup, network, and provider data may be absent or restricted. Unknown values remain unknown rather than guessed.
