# Deepest Network Control (DNC)

> Full uBlock Origin-level network control for Android. System-wide ad blocking, redirect interception, and deep network filtering via local VPN.

## What It Does

- **DNS-level blocking** — Block entire domains at the DNS level (like AdGuard DNS, but local)
- **HTTP request filtering** — Block specific URLs by path, not just domain
- **Redirect blocking** — Intercept and block HTTP 301/302 redirects BEFORE the browser follows them (DNS-only blockers can't do this)
- **HTTPS inspection** — MITM proxy with user-installed CA certificate for deep HTTPS filtering
- **SNI-based filtering** — Block HTTPS connections by domain even without MITM
- **Full uBlock Origin filter syntax** — ABP, uBO, and AdGuard filter list support
- **Custom rules** — Add your own blocking/exception rules
- **Per-app exclusion** — Exclude specific apps from the VPN
- **Live request log** — See every request, filter match, and blocked redirect

## Architecture

```
Android VpnService → TUN Interface → Packet Parser
    ├── DNS Queries → DNS Interceptor → Filter Engine
    ├── HTTP (port 80) → HTTP Proxy → Filter + Redirect Blocker
    ├── HTTPS (port 443) → SNI Parser → MITM Proxy (optional)
    └── Other traffic → Direct forwarding
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Kotlin |
| Filter Engine | Custom ABP/uBO parser + URL matcher |
| VPN Layer | Android VpnService + TUN interface |
| HTTP/HTTPS Proxy | Custom Kotlin proxy |
| MITM/TLS | Java SSLEngine + Android Keystore |
| UI | Jetpack Compose + Material 3 |
| Async | Kotlin Coroutines |

## Filter Lists Supported

- EasyList
- EasyPrivacy
- uBlock Origin Filters
- Peter Lowe's List
- AdGuard Mobile Ads Filter
- Any custom ABP/uBO/AdGuard filter list URL

## Building

```bash
git clone https://github.com/dnc-project/deepest-network-control.git
cd deepest-network-control
./gradlew assembleDebug
```

Or use GitHub Actions to build the APK automatically.

## License

GPL-3.0
