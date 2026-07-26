# Tunnel layer (Network Extension)

Extension target `tunnel` — runtime, где живёт SSTP-сессия и packet flow.

## Файлы

| Файл | Назначение |
|------|------------|
| `tunnel/PacketTunnelProvider.m` | Entry point NEPacketTunnelProvider |
| `tunnel/PacketTunnelProvider.h` | Интерфейс |
| `tunnel/Info.plist` | Extension point + principal class |
| `tunnel/tunnel.entitlements` | packet-tunnel-provider |
| `tunnel/cacert.pem` | Bundled Mozilla CA roots for OpenSSL verify |
| `shared/SSTPShared.h` | Общие константы app ↔ extension |

Principal class: `PacketTunnelProvider`  
NSExtensionPointIdentifier: `com.apple.networkextension.packet-tunnel`

## Start tunnel

```objc
- (void)startTunnelWithOptions:(NSDictionary *)options
             completionHandler:(void (^)(NSError *))completionHandler
```

Источники credentials (по приоритету):

| Поле | Источник |
|------|----------|
| server | `options[@"server"]` → иначе `protocolConfiguration.serverAddress` |
| username | `options[@"username"]` → иначе `protocolConfiguration.username` |
| password | `options[@"password"]` → иначе dereference `passwordReference` |
| tlsMode / caPem / pinSha256 | options → иначе `providerConfiguration` |

При отсутствии server/username/password → `missing_credentials` (domain `ru.altatec.sstp`).

### Worker thread

Сессия SSTP блокирует libevent loop, поэтому:

1. `sstp_ios_session_create(on_ready, on_packet, on_stage, on_fail, self)`
2. На фоневом `NSThread`:
   - `sstp_ios_session_start_ex(...)`
   - `sstp_ios_session_run(...)`

Stop ждёт worker с timeout **5s**, затем `session_free`.  
Callbacks после teardown игнорируются через `sessionGeneration`.

## Errors / status channel

- C fail → `NSError` domain `ru.altatec.sstp` + `userInfo` keys `code` / `stage` / `NSLocalizedDescriptionKey`
- `handleAppMessage` / `get_status` → JSON `{ stage, connected, lastError, reconnectAttempt }`
- App Groups не используются (текущие App Store profiles без `application-groups`); app поллит `get_status` во время Connecting

## Reconnect

Transient codes (`dns_resolve`, `tcp_timeout`, `tls_handshake`, `network_lost`, …): до **3** попыток, backoff 1s / 2s / 5s.  
Fatal (`auth_rejected`, `tls_cert`, `missing_credentials`, `cancelled`, `crypto_binding`) — без retry.  
User stop → `cancelled`, reconnect отключён.

## Callbacks → NE

### `on_stage`

Обновляет текущую стадию и App Group.

### `on_ready`

`applyTunnelSettings…` → IPv4 default route, DNS, MTU 1400 → `startPacketLoop` → start completion(nil).

### `on_packet`

Пишет пакет в `packetFlow` как `AF_INET`.

### `on_fail`

Structured `(code, stage, message)` → reconnect policy или `cancelTunnelWithError`.

## Packet loop

```text
readPacketsWithCompletionHandler
  → for each packet with AF_INET / AF_INET6
       sstp_ios_session_write_ip(session, bytes, length)
  → recurse while packetLoopRunning
```

## Где править

| Задача | Место |
|--------|-------|
| MTU / routes / DNS defaults | `applyTunnelSettings...` |
| Credentials / Keychain ref / TLS config | `startTunnelWithOptions` |
| Reconnect policy | `handleSessionFailureWithCode…` |
| App messages / App Group | `handleAppMessage`, `persistStatus` |
| Threading / lifecycle session | start/stop методы |

Сам протокол SSTP/PPP — см. [sstp-engine.md](sstp-engine.md).
