# System Config Inspector

A lightweight, read-only **Universal Linux Environment Inspector** with both a terminal report and a professional browser dashboard. It uses Python's standard library only, including the built-in `http.server`; it has no third-party packages, frontend framework, cloud SDK, database, telemetry, runtime installation, or external network calls.

The same one-time inspection result powers both the CLI output and the dashboard. Values are never fabricated: unavailable metrics are displayed as `Unknown / Not exposed`.

## Modes

One-shot CLI inspection:

```bash
python system_info.py --once
```

Long-running browser dashboard:

```bash
python system_info.py --serve
```

The environment variable `INSPECTOR_MODE=once|serve` can select the mode. If no mode is specified, the default is `serve`, which is appropriate for a Render Web Service. `start.sh` launches serve mode by default and honors `INSPECTOR_MODE=once` when explicitly set.

## Browser dashboard

The standard-library HTTP server binds to `0.0.0.0:$PORT`, using port `10000` only when `PORT` is absent or invalid. It performs the inspection once at startup, stores the structured result in memory, and does not re-run collectors for requests.

| Method | Route | Behavior |
|---|---|---|
| `GET` | `/` | Responsive HTML dashboard containing every successfully collected metric. |
| `GET` | `/healthz` | HTTP 200 with `ok`. |
| `HEAD` | `/`, `/healthz` | Header-only equivalent. |
| Other | Any route | HTTP 404. |

The dashboard is built entirely with semantic HTML, inline CSS, responsive cards, tables, badges, collapsible metric sections, monospace technical values, source/scope labels, and a reliable visible-memory progress indicator. It loads no external CSS, JavaScript, fonts, images, or APIs.

Every metric is shown with an explanatory source and scope where useful. For example, cgroup CPU is labeled as allocated/enforced, while `/proc` CPU and memory values are labeled as visible runtime resources. Host-visible resources are never presented as service allocations.

## Dashboard sections

The dashboard includes overview cards and detailed sections for system identity, resource allocation, CPU, memory, storage, container/cgroup state, namespaces, process state, network metadata, Python runtime, process resource limits, virtualization, security, provider/platform evidence, and the safe environment allowlist.

The inspector reports CPU topology, model, vendor, logical/online/offline counts, frequency, flags, affinity, cgroup quota/period/weight, cpuset, calculated vCPU, and provider-reported allocation. Memory reporting separates host-visible memory from cgroup allocation/limit, current/high/max/swap limits, pressure, and events. Storage reporting separates visible filesystem capacity from provider disk allocation and includes filesystem, mount, inode, and block-device details where exposed.

## Security and privacy

The service is read-only. HTTP requests cannot execute commands, modify files, modify environment variables, or trigger another inspection. No external DNS or network requests are performed.

The environment is never dumped blindly. Only explicitly allowlisted deployment metadata is eligible for display, and secret-like names or credential-bearing values are omitted. This includes passwords, tokens, API keys, authentication values, private keys, database URLs, connection strings, JWTs, cookies, sessions, certificates, SSH values, and other secret indicators. The report includes:

```text
Secret-like and non-allowlisted environment variables are intentionally omitted.
```

## Deployment

### Render Web Service

Use the repository as a Render Web Service with:

```text
Build Command: No build command required
Start Command: python system_info.py --serve
```

The service reads Render's `PORT`, binds to `0.0.0.0`, prints the complete CLI report to stdout, serves the dashboard at `/`, responds to `/healthz`, and remains alive until shutdown.

### Native Python

```bash
python system_info.py --serve
```

For a one-shot environment:

```bash
python system_info.py --once
```

### Docker

```bash
docker build -t system-config-inspector .
docker run --rm -e PORT=10000 -p 10000:10000 system-config-inspector
```

The Dockerfile uses the official `python:3.12-slim` image, installs nothing, starts `start.sh`, and keeps the web service in the foreground. The same image can run one-shot mode with `-e INSPECTOR_MODE=once`.

### VPS or bare metal

Run the service under the platform's process supervisor or directly in the foreground:

```bash
PORT=10000 python system_info.py --serve
```

The service handles `SIGTERM` and `SIGINT`, prints a concise shutdown message, closes the listener, and exits cleanly.

## CLI report and portability

The CLI report remains available and contains readable sections for:

`SYSTEM`, `CPU`, `MEMORY`, `STORAGE`, `CONTAINER / CGROUP`, `NAMESPACES`, `PROCESS`, `NETWORK`, `RUNTIME`, `RESOURCE ALLOCATION`, `RESOURCE LIMITS`, `VIRTUALIZATION`, `SECURITY`, `PLATFORM`, and `SAFE ENVIRONMENT`.

The implementation supports standard Linux environments, Docker, Docker Compose, Kubernetes, ECS/Fargate, EC2, Render, Railway, Fly.io, VPSs, virtual machines, bare metal, x86_64, ARM64/aarch64, cgroup v1, cgroup v2, restricted permissions, and partially unavailable `/proc` or `/sys` files. Each collector is isolated so one missing source cannot prevent the rest of the report or dashboard from rendering.

Provider detection uses strong explicit evidence only. Examples include `RENDER=true`, `AWS_EXECUTION_ENV=AWS_ECS_FARGATE`, ECS metadata variables, and `KUBERNETES_SERVICE_HOST`. Hostnames, IP addresses, CPU models, kernels, filesystems, and arbitrary strings are not used to guess providers.

## Validation

```bash
python3 -m py_compile system_info.py
bash -n start.sh
python system_info.py --once
PORT=10000 python system_info.py --serve
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

The inspector can only report what the current runtime exposes. A container may not see the physical host's complete hardware configuration, and visible filesystem capacity is not automatically provider persistent-disk allocation. Cgroup, namespace, security, DMI, network, and provider data may be restricted or unavailable. Unknown values remain unknown rather than guessed.
