# System Config Inspector

A lightweight, read-only **Universal Linux Environment Inspector** for containers, VPSs, VMs, bare metal, Kubernetes, Render, AWS ECS/Fargate, Docker and similar Linux runtimes.

It uses **Python standard library only**. There is **no browser GUI/dashboard**, no RDP/VNC, no frontend framework, no database, no telemetry and no external network dependency.

The primary output is the terminal-style report:

```text
SYSTEM CONFIGURATION INSPECTOR
Read-only inspection using Python standard library; no external network calls.

================ SYSTEM ================
OS                                 Linux
...
```

## Modes

### One-shot

```bash
python system_info.py --once
```

Prints the complete report and exits.

### Deployment / long-running mode

```bash
python system_info.py --serve
```

The inspector prints the report to stdout and then keeps a minimal standard-library HTTP listener alive so platforms such as Render Web Services do not terminate the process.

**Important:** this is not a GUI. The root URL returns the **same plain-text report** that is printed in the terminal/logs.

| Method | Route | Behavior |
|---|---|---|
| `GET` | `/` | Complete plain-text system configuration report. |
| `GET` | `/healthz` | `200 ok` health response. |
| Other | Any route | `404 Not Found`. |

The report is generated once at startup and the same immutable report is served at `/`. A browser therefore shows the terminal-style configuration text rather than cards, charts or HTML UI.

`INSPECTOR_MODE=once|serve` can select the mode. `--once` and `--serve` take precedence over the environment variable.

## What it inspects

- **SYSTEM** — OS, distribution, kernel, architecture, hostname, uptime, boot time, timezone, locale, init/systemd, user and shell.
- **CPU** — model, vendor, architecture, logical/online/offline CPUs, topology, frequency, flags, affinity, quota, period, weight/shares, cpuset, calculated vCPU and provider-reported allocation.
- **MEMORY** — visible memory, available/used/free, buffers/cache, cgroup current/high/max, allocation/limit, swap, pressure and events.
- **STORAGE** — visible root filesystem capacity, usage, free space, filesystem type, mount information, options, read-only state, inodes, filesystems and block devices. Provider disk allocation is kept separate.
- **CONTAINER / CGROUP** — container evidence, confidence, cgroup v1/v2, path, controllers, CPU/memory/PID/I/O limits.
- **NAMESPACES** — PID, mount, network, IPC, UTS, user and cgroup namespaces.
- **PROCESS** — PID/PPID, executable, command line, UID/GID, groups, threads, state and process limits.
- **NETWORK** — local interfaces, state, MAC, MTU, routes, default route, DNS configuration and `/etc/hosts`. No external requests are made.
- **RUNTIME** — Python version, implementation, executable, architecture, compiler, build, cwd, prefixes and virtualenv state.
- **RESOURCE ALLOCATION** — enforced cgroup CPU, memory and PID allocation separated from visible host resources.
- **RESOURCE LIMITS** — relevant process `RLIMIT_*` values.
- **VIRTUALIZATION** — local evidence and confidence.
- **SECURITY** — root status, capabilities, no-new-privileges, seccomp, AppArmor, SELinux and filesystem read-only state.
- **PLATFORM** — strong provider detection with confidence and evidence.
- **SAFE ENVIRONMENT** — only explicitly allowlisted deployment metadata.

## Resource terminology

The inspector deliberately distinguishes:

1. **Host-visible resources** — what `/proc`, `/sys` or the mounted filesystem exposes.
2. **Container-visible resources** — what the current namespace/container exposes.
3. **Enforced/allocated resources** — cgroup limits that actually constrain the workload.
4. **Provider-reported resources** — explicit values supplied by a platform.

A visible 30 GB host memory value must not be presented as a 512 MB service allocation. Likewise, visible filesystem capacity is not automatically the provider's persistent disk allocation.

Unlimited cgroup sentinel values are displayed as `Unlimited / No enforced limit`; huge Linux v1 sentinel numbers are not displayed as absurd PB values.

## Provider detection

Provider detection uses strong explicit evidence rather than weak guesses. Examples:

- Render: `RENDER=true` or explicit Render service variables.
- AWS ECS/Fargate: `AWS_EXECUTION_ENV=AWS_ECS_FARGATE`.
- AWS ECS: ECS metadata environment variables.
- Kubernetes: `KUBERNETES_SERVICE_HOST`.
- Cloud Run: `K_SERVICE` / `K_REVISION`.
- Railway, Fly.io, Vercel and Heroku: explicit platform variables.

Hostnames, IP addresses, CPU model names and generic kernel strings are not sufficient provider evidence.

## cgroup and architecture support

Supports cgroup v1 and v2 and common Linux architectures including x86_64/amd64 and aarch64/arm64.

Unavailable values remain:

```text
Unknown / Not exposed
```

A CPU model that is missing or numeric garbage is never reported as fake `0`.

## Security and privacy

The environment is not dumped wholesale. Only allowlisted deployment metadata is eligible for output. Secret-like names such as passwords, tokens, API keys, credentials, private keys, database URLs, connection strings, JWTs, cookies, sessions, certificates and SSH values are omitted.

## Deployment

### Render Web Service

```text
Build Command: No build command required
Start Command: python system_info.py --serve
```

The process binds to `0.0.0.0:$PORT`, prints the full report to Render logs, keeps running, and makes the exact same report available as plain text at the service root URL.

### Docker

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

### Native Linux / VPS / VM / bare metal

```bash
python3 system_info.py --once
```

or:

```bash
PORT=10000 python3 system_info.py --serve
```

## Validation

```bash
python3 -m py_compile system_info.py
bash -n start.sh
python3 system_info.py --once
PORT=10000 python3 system_info.py --serve
curl -i http://127.0.0.1:10000/
curl -i http://127.0.0.1:10000/healthz
```

## Limitations

The inspector can only report what the current runtime exposes. Containers may hide physical host hardware, provider disk allocation, IP details, security controls or cgroup information. Unknown values remain unknown rather than guessed.
