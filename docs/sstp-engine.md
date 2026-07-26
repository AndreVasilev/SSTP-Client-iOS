# SSTP engine (C)

Низкоуровневый движок в `sstp/`. Используется extension’ом через публичный API `sstp-ios.h`.

## Публичный API для iOS

Файл: `sstp/sstp-ios.h`

```c
typedef struct sstp_ios_session sstp_ios_session_t;

typedef void (*sstp_ios_ready_fn)(void *ctx,
                                  const char *local_ip,
                                  const char *gateway_ip,
                                  const char *dns1,
                                  const char *dns2);
typedef void (*sstp_ios_packet_fn)(void *ctx, const uint8_t *ip_packet, size_t len);
typedef void (*sstp_ios_fail_fn)(void *ctx, const char *message);

sstp_ios_session_t *sstp_ios_session_create(...);
int  sstp_ios_session_start(session, server, username, password);
int  sstp_ios_session_write_ip(session, ip_packet, len);
void sstp_ios_session_run(session);    // блокирует на event loop
void sstp_ios_session_stop(session);
void sstp_ios_session_free(session);
```

Реализация: `sstp/sstp-ios.c`.

## Lifecycle сессии

```text
create
  → start
       OpenSSL init
       options: NOLAUNCH | NOPLUGIN | CERTWARN | NODAEMON | TLSEXT
       URL: https://<server>/  (port default 443)
       event_base + socketpairs (inject IP, stop)
       sstp_stream_create / connect (timeout 60)
  → run  (event_base_dispatch)
       TLS connected
       → HTTP SSTP handshake (sstp-http)
       → SSTP state machine (sstp-state)
       → CALL_CONNECT
            sstp_pppd_create/start  (реализация = ios-pppd.c)
            LCP → MSCHAPv2 → IPCP → CCP/MPPE
       → PPP AUTH: derive MPPE keys → sstp_state_mppe_keys
       → PPP UP: sstp_state_accept (crypto binding) → on_ready
       → data path: SSTP data ↔ PPP ↔ IP callbacks
  → stop / fail → loopbreak
  → free resources
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
| `sstp-stream.c` | TCP/TLS stream на OpenSSL + libevent |
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

## TLS notes (текущее поведение)

В `sstp-ios.c`:

- `SSLv23_client_method()`, отключены SSLv2/SSLv3/compression
- `SSL_VERIFY_NONE`
- включён `SSTP_OPT_CERTWARN` — проблемы сертификата логируются, соединение может продолжаться

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
| PPP negotiation / MPPE | `ios-pppd.c` |
| MSCHAPv2 math | `sstp-mschapv2.c` |
| SSTP control messages / binding | `sstp-state.c`, `sstp-packet.c`, `sstp-cmac.c` |
| TLS/stream | `sstp-stream.c`, куски `sstp-ios.c` |
| HTTP handshake | `sstp-http.c` |

## Связанные документы

- Tunnel bridge → [tunnel-layer.md](tunnel-layer.md)
- Тесты → [build-test-ci.md](build-test-ci.md)
