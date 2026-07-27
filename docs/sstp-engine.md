# SSTP engine (C)

Низкоуровневый движок в `sstp/`. Используется extension’ом через публичный API `sstp-ios.h`.

## Публичный API для iOS

Файлы: `sstp/sstp-ios.h`, `sstp/sstp-ios-error.h`

```c
typedef void (*sstp_ios_ready_fn)(...);
typedef void (*sstp_ios_packet_fn)(...);
typedef void (*sstp_ios_stage_fn)(void *ctx, const char *stage);
typedef void (*sstp_ios_fail_fn)(void *ctx, const char *code,
                                 const char *stage, const char *message);

sstp_ios_session_t *sstp_ios_session_create(on_ready, on_packet, on_stage, on_fail, ctx);
int  sstp_ios_session_start(session, server, username, password);
int  sstp_ios_session_start_ex(session, const sstp_ios_start_params_t *params);
int  sstp_ios_session_write_ip(session, ip_packet, len);
void sstp_ios_session_run(session);    // блокирует на event loop
void sstp_ios_session_stop(session);
void sstp_ios_session_free(session);
```

`sstp_ios_start_params_t` добавляет TLS trust:

| Поле | Назначение |
|------|------------|
| `tls_mode` | `SYSTEM` / `CUSTOM_CA` / `PINNED` / `INSECURE_DEBUG` (только Debug) |
| `ca_pem` / `ca_pem_len` | PEM для custom CA |
| `pin_sha256_hex` | SHA-256 fingerprint листа (64 hex) |

Стабильные коды/стадии — в `sstp-ios-error.h` (`dns_resolve`, `tls_cert`, `auth_rejected`, …).  
`sstp_ios_error_is_fatal(code)` определяет, можно ли auto-reconnect.

Реализация: `sstp/sstp-ios.c`, хелперы контракта — `sstp/sstp-ios-error.c`,
iOS trust — `sstp/sstp-ios-trust.m`.

## Lifecycle сессии

```text
create
  → start_ex
       OpenSSL init
       options: NOLAUNCH | NOPLUGIN | NODAEMON | TLSEXT
                (+ CERTWARN только для INSECURE_DEBUG)
       TLS: SYSTEM → SecTrust (iOS trust store); CUSTOM_CA / PINNED → OpenSSL
       URL: https://<server>/  (port default 443)
       stages: resolving → tcp_tls → http_upgrade → sstp_control
               → ppp_* → applying_settings
       event_base + socketpairs (inject IP, stop)
       sstp_stream_create / connect (timeout 60)
  → run  (event_base_dispatch)
       TLS connected (+ SecTrust for SYSTEM; fail → tls_cert)
       → HTTP SSTP handshake (sstp-http)
       → sstp_verify_cert(CERT|NAME) for non-SYSTEM — fail → tls_cert (abort)
       → SSTP state machine (sstp-state)
       → CALL_CONNECT
            sstp_pppd_create/start  (реализация = ios-pppd.c)
            LCP → MSCHAPv2 → IPCP → CCP/MPPE
       → PPP AUTH: derive MPPE keys → sstp_state_mppe_keys
       → PPP AUTH_FAIL → auth_rejected (fatal)
       → PPP UP: sstp_state_accept (crypto binding) → on_ready
       → data path: SSTP data ↔ PPP ↔ IP callbacks
  → stop / fail → loopbreak
  → free resources (password memory scrubbed)
```

Cross-thread IP injection: `write_ip` пишет в socketpair; callback в libevent thread вызывает `sstp_pppd_send_ip`.

## ios-pppd vs sstp-pppd

| Файл | Роль | В Xcode Sources? |
|------|------|------------------|
| `sstp/ios-pppd.c` | In-process PPP для Network Extension | **Да** |
| `sstp/sstp-pppd.c` | Оригинальный запуск внешнего `pppd` | **Нет** |

`ios-pppd.c` экспортирует тот же набор `sstp_pppd_*`, который вызывает `sstp-ios.c`:

- `sstp_pppd_create` / `start` / `stop` / `free`
- `sstp_pppd_send` / `sstp_pppd_send_ip`
- `sstp_pppd_getchap` / `sstp_pppd_get_ipv4`
- `sstp_pppd_set_mppe_keys` / `sstp_pppd_set_ip_handler`

PPP events: `SSTP_PPP_DOWN`, `UP`, `AUTH`, `START`, `AUTH_FAIL`.

### PPP phases в ios-pppd

1. LCP configure
2. CHAP MSCHAPv2 (`0xc223` / `0x81`)
3. IPCP → local/peer/DNS
4. CCP / MPPE (stateless + 128-bit; если reject — может продолжить без MPPE)
5. IP data (опционально RC4 MPPE)

MRU: `1400`.

## Auth / crypto helpers

`sstp/sstp-mschapv2.c` (+ `.h`):

- NT password hash (MD4 over UTF-16LE)
- Challenge hash (SHA1)
- NT response (DES)
- Хелперы для MPPE key material (совместно с `sstp-chap` / ios-pppd)

Тесты векторов: `tests/test_mschapv2.c`.

## Основные модули SSTP (shared library code)

| Модуль | Назначение |
|--------|------------|
| `sstp-stream.c` | TCP/TLS stream на OpenSSL + libevent; hostname via `X509_check_host` / `X509_check_ip_asc` |
| `sstp-http.c` | HTTP upgrade / SSTP handshake |
| `sstp-packet.c` | Framing control/data packets |
| `sstp-state.c` | Control state machine, crypto binding |
| `sstp-cmac.c` | CMAC / binding helpers |
| `sstp-chap.c` | CHAP/MPPE key derivation helpers |
| `sstp-buff.c` | Буферы |
| `sstp-fcs.c` | PPP/HDLC FCS |
| `sstp-client.c` | Оригинальный client orchestration (Linux-oriented) |
| `sstp-option.c` | Парсер опций / URL helpers |
| `sstp-util.c` | Утилиты (в т.ч. URL parse — покрыт тестом) |
| `sstp-log*.c` | Логирование |
| `config.h` | iOS feature flags (`SSTP_IOS`, без ppp plugin/netlink/pty) |

## TLS trust policy

В `sstp-ios.c` / `sstp-stream.c`:

| Mode | Поведение |
|------|-----------|
| `SYSTEM` (default) | **iOS SecTrust** (системные + MDM/корпоративные корни) + hostname via SSL policy; OpenSSL не режет цепочку по Mozilla CA |
| `CUSTOM_CA` | PEM из params → `X509_STORE_add_cert` (OpenSSL) |
| `PINNED` | SHA-256 pin листа; mismatch → `tls_cert` |
| `INSECURE_DEBUG` | Только Debug; `SSL_VERIFY_NONE` + `CERTWARN` |

TLS handshake выполняется **явно после TCP connect** (до HTTP SSTP upgrade), чтобы ошибки сертификата не маскировались под `http_upgrade`.

В `SYSTEM` после handshake цепочка (leaf + intermediates) передаётся в `SecTrustEvaluateWithError` (`sstp-ios-trust.m`). Корпоративный CA, уже установленный на iOS, принимается без PEM в UI.

На fail verify: abort с `tls_cert`, **без** continue.  
CA bundle `tunnel/cacert.pem` остаётся для OpenSSL-режимов (и soft-load в SYSTEM).

## config.h

`sstp/config.h` — iOS-адаптированный autoconf-подобный конфиг:

- `HAVE_LIBEVENT` / `HAVE_LIBEVENT2`
- `#undef HAVE_PPP_PLUGIN`, `HAVE_NETLINK`, `HAVE_PTY_H`, `HAVE_FORK`
- `SSTP_IOS 1`
- `PACKAGE_VERSION "1.0.0"`

## Где править

| Задача | Файлы |
|--------|-------|
| Публичный session API / connect options | `sstp-ios.h`, `sstp-ios.c` |
| Error/stage contract | `sstp-ios-error.h`, `sstp-ios-error.c` |
| PPP negotiation / MPPE | `ios-pppd.c` |
| MSCHAPv2 math | `sstp-mschapv2.c` |
| SSTP control messages / binding | `sstp-state.c`, `sstp-packet.c`, `sstp-cmac.c` |
| TLS/stream / hostname | `sstp-stream.c`, куски `sstp-ios.c` |
| HTTP handshake | `sstp-http.c` |

## Связанные документы

- Tunnel bridge → [tunnel-layer.md](tunnel-layer.md)
- Тесты → [build-test-ci.md](build-test-ci.md)
- Backlog (выполнено) → [backlog/vpn-production-quality.md](backlog/vpn-production-quality.md), [backlog/tls-certificate-verification.md](backlog/tls-certificate-verification.md)
