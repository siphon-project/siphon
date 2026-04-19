# SIPhon Feature Readiness Matrix

## Overview

This document tracks the maturity of every SIPhon feature across three readiness levels. The only production deployment to date is a registrar/proxy role — features validated there are marked accordingly.

| Readiness | Meaning |
|-----------|---------|
| **Production** | Running on live traffic today |
| **Implemented** | Code-complete, unit/integration tested, not yet production-deployed |
| **Planned** | Partially wired or design-only |

---

## Core SIP Engine

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Stateful proxy (RFC 3261 §16) | **Production** | `script: @proxy.on_request` | Full transaction state machines; ICT Timer A RFC-compliant (capped at T2, fires in Proceeding, cancelled on final response) |
| B2BUA (RFC 3261 §6) | Implemented | `script: @b2bua.on_invite` | Two-leg call control, per-leg Call-ID + From-tag, topology hiding |
| Parallel forking | **Production** | `request.fork()` | Used for AS→subscriber delivery |
| Sequential forking | Implemented | `request.fork(strategy="sequential")` | |
| Record-Route / Loose Route | **Production** | `request.record_route()` | Mid-dialog routing proven |
| CANCEL propagation | **Production** | Core | Matched to transaction automatically |
| In-dialog sequential routing | **Production** | `request.loose_route()` | |
| Call transfer (REFER, RFC 3515) | Implemented | B2BUA `@b2bua.on_refer` | |
| Session timers (RFC 4028) | Implemented | `session_timer:` | UAC/UAS/B2BUA refresher modes |
| PRACK (RFC 3262) | Implemented | Core | Reliable provisional responses |

## Transports

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| TCP | **Production** | `listen.tcp` | AS-facing; RFC 3261 §18.3 stream framing with Content-Length extraction |
| TLS | **Production** | `listen.tls` | Subscriber-facing, TLS 1.3 validated; RFC 3261 §18.3 stream framing |
| TLS 1.3 | **Production** | `tls.method: TLSv1_3` | |
| TLS 1.2 | Implemented | `tls.method: TLSv1_2` | |
| mTLS (client cert verification) | Implemented | `tls.verify_client: true` | |
| UDP | Implemented | `listen.udp` | Not used in current deployment |
| WebSocket (WS) | Implemented | `listen.ws` | RFC 7118, browser/WebRTC clients |
| Secure WebSocket (WSS) | Implemented | `listen.wss` | |
| SCTP | Implemented | `listen.sctp` | RFC 4168, IMS inter-node |
| Per-socket advertised address | **Production** | `listen.tls[].advertise` | |
| Global advertised address | Implemented | `advertised_address:` | Fallback for 0.0.0.0 binds |
| DSCP/ToS marking | Implemented | `listen.dscp` | RFC 4594 signaling QoS; default CS3 (24); per-listener override |

## Registrar

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Redis backend | **Production** | `registrar.backend: redis` | Persistent across restarts |
| Memory backend | Implemented | `registrar.backend: memory` | Ephemeral |
| PostgreSQL backend | Implemented | `registrar.backend: postgres` | |
| Python custom backend | Implemented | `registrar.backend: python` | |
| Expires control (default/min/max) | **Production** | `registrar.{default,min,max}_expires` | |
| Max contacts per AoR | **Production** | `registrar.max_contacts` | |
| Redis TTL slack | **Production** | `registrar.redis.ttl_slack_secs` | Race condition buffer |
| GRUU (RFC 5627) | Implemented | | |
| Service-Route (RFC 3608) | Implemented | | |
| Registration state change hooks | **Production** | `@registrar.on_change` | Callbacks on insert/delete/expire |
| Outbound registration (registrant) | Implemented | `registrant:` | UAC REGISTER to upstream trunks |

## Authentication

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Digest auth — 401 (UAS) | **Production** | `auth.require_digest()` | REGISTER challenges |
| Digest auth — 407 (proxy) | **Production** | `auth.require_proxy_digest()` | INVITE challenges |
| HTTP backend (HA1 lookup) | **Production** | `auth.backend: http` | REST credential lookup |
| Static users backend | Implemented | `auth.backend: static` | Inline config credentials |
| Diameter Cx backend (HSS) | Implemented | `auth.backend: diameter_cx` | 3GPP TS 29.228 |
| AKA / AKAv1-MD5 | Implemented | `auth.aka_credentials` | 3GPP TS 33.203 + Milenage |
| SHA-256 digest (RFC 7616) | Implemented | | |
| Anti-spoofing (from=auth check) | **Production** | Script logic | `auth_user == from_uri.user` |

## Security

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Rate limiting (per source IP) | **Production** | `security.rate_limit` | Window + ban duration |
| Scanner UA blocking | **Production** | `security.scanner_block` | sipvicious, friendly-scanner, etc. |
| Trusted CIDRs (bypass rate limit) | **Production** | `security.trusted_cidrs` | |
| Failed auth ban | **Production** | `security.failed_auth_ban` | Threshold + ban duration |
| APIBan integration | **Production** | `security.apiban` | Community IP blocklist polling |
| IP ACLs (allow/deny CIDR lists) | Implemented | Transport-level ACL | |
| Preloaded Route rejection | **Production** | Script logic | Anti-abuse for Route header |

## NAT Traversal

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Force rport (RFC 3581) | **Production** | `nat.force_rport: true` | |
| Fix Contact (observed source) | **Production** | `nat.fix_contact: true` | |
| Fix REGISTER Contact | **Production** | `nat.fix_register: true` | |
| Fix NATed Contact (script) | **Production** | `request.fix_nated_contact()` | |
| NAT keepalive (OPTIONS ping) | Implemented | `nat.keepalive` | Configurable interval + failure threshold |
| CRLF keepalive (RFC 5626 §4.4.1) | Implemented | `nat.crlf_keepalive` | TCP/TLS/WS connection keep-alive |
| Stale contact eviction on restart | **Production** | Core | Evicts connection-oriented contacts + on_change notify |
| Outbound flow tokens (RFC 5626) | Implemented | | Via/Route flow tokens |

## Media

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| RTPEngine integration (NG protocol) | Implemented | `media.rtpengine` | Single or multi-instance |
| RTPEngine load balancing | Implemented | `media.rtpengine.instances[]` | Weighted distribution |
| Built-in profile: SRTP↔RTP | Implemented | `srtp_to_rtp` | SRTP UE ↔ RTP core |
| Built-in profile: WS↔RTP | Implemented | `ws_to_rtp` | WebSocket UE ↔ RTP core |
| Built-in profile: WSS↔RTP | Implemented | `wss_to_rtp` | DTLS-SRTP/AVPF + ICE ↔ RTP |
| Built-in profile: RTP passthrough | Implemented | `rtp_passthrough` | IMS-internal |
| Custom media profiles | Implemented | `media.profiles` | User-defined NG flags |
| SDP manipulation (`sdp` namespace) | Implemented | None | Parse/modify/apply SDP from Python scripts |
| SDP attribute get/set/remove | Implemented | None | Session and media-level `a=` attributes |
| SDP codec filtering | Implemented | None | `filter_codecs()` / `remove_codecs()` |
| SDP media section removal | Implemented | None | `remove_media("video")` |

## Gateway Routing & Load Balancing

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Destination groups | Implemented | `gateway.groups` | |
| Round-robin algorithm | Implemented | `algorithm: round_robin` | |
| Weighted algorithm | Implemented | `algorithm: weighted` | |
| Hash-based algorithm | Implemented | `algorithm: hash` | |
| SIP OPTIONS health probing | Implemented | `gateway.groups[].probe` | Configurable interval + failure threshold |
| Priority-based failover tiers | Implemented | `destinations[].priority` | |
| Dynamic group management | Implemented | Python `gateway.add_group()` / `gateway.remove_group()` | |
| Destination up/down marking | Implemented | Python `gateway.mark_up()` / `gateway.mark_down()` | |

## Call Detail Records

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| CDR generation | Implemented | `cdr:` | |
| File backend (JSON-lines) | Implemented | `cdr.backend: file` | With rotation |
| Syslog backend | Implemented | `cdr.backend: syslog` | UDP syslog |
| HTTP webhook backend | Implemented | `cdr.backend: http` | POST with optional auth header |
| REGISTER event inclusion | Implemented | `cdr.include_register` | Off by default |
| Script-injected extra fields | Implemented | | |

## SIP Tracing

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| HEP v3 over UDP | **Production** | `tracing.hep` | Homer integration |
| HEP over TCP | Implemented | `tracing.hep.transport: tcp` | |
| HEP over TLS | Implemented | `tracing.hep.transport: tls` | With CA cert + SNI |
| Custom agent ID | **Production** | `tracing.hep.agent_id` | |
| Error log suppression | **Production** | `tracing.hep.error_log_interval` | Configurable interval |

## Metrics & Monitoring

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Prometheus endpoint | **Production** | `metrics.prometheus` | |
| Request/response counters | **Production** | `siphon_requests_total` / `siphon_responses_total` | |
| Active registrations gauge | **Production** | `siphon_registrations_active` | |
| Active transactions gauge | **Production** | `siphon_transactions_active` | |
| Active dialogs gauge | **Production** | `siphon_dialogs_active` | |
| Active connections (by transport) | **Production** | `siphon_connections_active` | |
| Request duration histogram | **Production** | `siphon_request_duration_seconds` | |
| Script execution counters | **Production** | `siphon_script_executions_total` | |
| Uptime gauge | **Production** | `siphon_uptime_seconds` | |
| Admin API — health | Implemented | `GET /admin/health` | Liveness/readiness probe |
| Admin API — stats | Implemented | `GET /admin/stats` | Aggregate counters |
| Admin API — registrations | Implemented | `GET/DELETE /admin/registrations` | List, detail, force-unregister |

## Logging

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| JSON structured logging | **Production** | `log.format: json` | |
| Pretty (human-readable) logging | Implemented | `log.format: pretty` | |
| File logging | **Production** | `log.file` | With logrotate support |
| Log level control | **Production** | `log.level` | debug/info/warn/error |

## Python Scripting

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Script loading | **Production** | `script.path` | |
| Hot-reload via inotify | **Production** | `script.reload: auto` | |
| Hot-reload via SIGHUP | Implemented | `script.reload: sighup` | |
| Proxy handlers (on_request/on_reply/on_failure) | **Production** | `@proxy.*` | on_request + on_reply proven |
| B2BUA handlers | Implemented | `@b2bua.*` | on_invite, on_answer, on_failure, on_bye, on_refer |
| Registrar hooks | **Production** | `@registrar.on_change` | |
| Auth API | **Production** | `auth.require_digest()` etc. | |
| Gateway API | Implemented | `gateway.select()` etc. | |
| Cache API | Implemented | `cache.fetch()` | |
| Presence API | Implemented | `presence.*` | |
| Lawful intercept API | Implemented | `li.*` | |
| Logging API | **Production** | `log.*` | |
| Async handler support | Implemented | | Auto-detected by runtime |
| Timer routes | Implemented | `@timer.every()`, `timer.set()`/`cancel()` | Periodic callbacks via Tokio; one-shot cancellable timers keyed by string |
| Mock SDK for testing | Implemented | `siphon-sdk` | Test scripts without Rust binary |

## Dialog Management

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Memory backend | **Production** | Default | In-process, ephemeral |
| Redis backend | Implemented | `dialog.backend: redis` | Persistent across restarts |
| PostgreSQL backend | Implemented | `dialog.backend: postgres` | |

## Named Cache

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Redis-backed cache | Implemented | `cache[].url` | |
| Local LRU tier | Implemented | `cache[].local_ttl_secs` | Two-tier: local + Redis |

## Presence

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| SUBSCRIBE/NOTIFY (RFC 6665) | Implemented | Python `presence` API | |
| PIDF (RFC 3863) | Implemented | | |
| Resource List Server (RFC 4662) | Implemented | | |
| Watcher Info (RFC 3857/3858) | Implemented | | |

## Server Identity

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Custom Server header | **Production** | `server.server_header` | |
| Custom User-Agent header | **Production** | `server.user_agent_header` | |

## Transaction Timers

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Non-INVITE timeout | **Production** | `transaction.timeout_secs` | |
| INVITE timeout | **Production** | `transaction.invite_timeout_secs` | |

## DNS Resolution

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| SRV lookup (RFC 3263) | Implemented | Core | With A/AAAA fallback |
| NAPTR support | Implemented | Core | |
| ENUM (RFC 6116) | Implemented | Core | |

---

## 3GPP / IMS / Telco

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Diameter Cx (HSS auth) | Implemented | `auth.backend: diameter_cx` | MAR/SAA, SAR/SAA, UAR/UAA, LIR/LIA |
| Diameter Sh (HSS user data) | Implemented | `diameter` | UDR/UDA, PUR/PUA, SNR/SNA, PNR/PNA — both HSS and AS roles (`sh_udr`/`sh_pur`/`sh_snr`, `@on_pnr`) |
| Diameter Ro (online charging) | Implemented | `diameter` | CCR/CCA |
| Diameter Rf (offline charging) | Implemented | `diameter` | ACR/ACA |
| Diameter Rx (policy/QoS) | Implemented | `diameter` | AAR/AAA, STR/STA, RAR/RAA |
| Diameter peer management | Implemented | `diameter.peers` | Failover + round-robin routing |
| AKA authentication (Milenage) | Implemented | `auth.aka_credentials` | 3GPP TS 33.203 / TS 35.206 |
| IPsec SA management (P-CSCF) | Implemented | `ipsec` | Protected client/server ports |
| Initial Filter Criteria (iFC) | Implemented | `isc` | XML trigger point matching |
| IMS P-CSCF role | Implemented | Example config + script | |
| IMS I-CSCF role | Implemented | Example config + script | |
| IMS S-CSCF role | Implemented | Example config + script | |
| 5G SBI — Npcf (policy) | Implemented | `sbi` | NRF discovery, OAuth2 |
| 5G SBI — Nchf (charging) | Implemented | `sbi` | |

## Lawful Intercept / Recording

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| LI master switch + audit log | Implemented | `lawful_intercept` | |
| ETSI X1 admin interface | Implemented | `lawful_intercept.x1` | HTTPS + mTLS + bearer token |
| ETSI X2 IRI delivery | Implemented | `lawful_intercept.x2` | TCP/TLS to mediation device |
| ETSI X3 CC delivery | Implemented | `lawful_intercept.x3` | RTPEngine mirror reception |
| SIPREC recording (RFC 7866) | Implemented | `lawful_intercept.siprec` | SIP Recording Server integration |

---

## Summary

| Category | Production | Implemented | Total |
|----------|-----------|-------------|-------|
| Transports | 3 (TCP, TLS, TLS 1.3) | 6 (UDP, WS, WSS, SCTP, mTLS, TLS 1.2) | 9 |
| Registrar | 5 (Redis, expires, max contacts, hooks, TTL slack) | 5 (memory, PG, Python, GRUU, Service-Route) | 10 |
| Authentication | 4 (HTTP/HA1, digest 401/407, anti-spoof) | 4 (static, Diameter Cx, AKA, SHA-256) | 8 |
| Security | 5 (rate limit, scanner, trusted CIDR, fail ban, APIBan) | 1 (IP ACLs) | 6 |
| NAT | 5 (rport, fix contact, fix register, script fixup, stale eviction) | 3 (keepalive, CRLF keepalive, flow tokens) | 8 |
| Media | 0 | 7 (RTPEngine, LB, 4 profiles, custom profiles) | 7 |
| Gateway routing | 0 | 7 (groups, 3 algorithms, probes, failover, dynamic) | 7 |
| CDR | 0 | 5 (file, syslog, HTTP, register events, extra fields) | 5 |
| Tracing | 3 (HEP v3 UDP, agent ID, error suppression) | 2 (TCP, TLS) | 5 |
| Metrics | 8 (Prometheus, all gauges/counters/histograms) | 3 (admin health, stats, registrations) | 11 |
| Scripting | 9 (proxy, registrar, auth, logging, header ops) | 7 (B2BUA, gateway, cache, presence, LI, async, SDK) | 16 |
| 3GPP/IMS | 0 | 14 (Diameter 5 apps, AKA, IPsec, iFC, 3 CSCFs, 2 SBI) | 14 |
| LI/Recording | 0 | 5 (X1, X2, X3, SIPREC, audit) | 5 |
| **Totals** | **~42** | **~69** | **~111** |
