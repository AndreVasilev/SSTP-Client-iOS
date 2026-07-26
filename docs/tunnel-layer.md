# Tunnel layer (Network Extension)

Extension target `tunnel` — runtime, где живёт SSTP-сессия и packet flow.

## Файлы

| Файл | Назначение |
|------|------------|
| `tunnel/PacketTunnelProvider.m` | Entry point NEPacketTunnelProvider |
| `tunnel/PacketTunnelProvider.h` | Интерфейс |
| `tunnel/Info.plist` | Extension point + principal class |
| `tunnel/tunnel.entitlements` | packet-tunnel entitlement |

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
| password | `options[@"password"]` |

Если password пустой, код **не** читает `passwordReference` (есть комментарий, что пароль должен прийти из app start options).

При отсутствии server/username/password → ошибка domain `ru.altatec.sstp`, code `1`.

### Worker thread

Сессия SSTP блокирует libevent loop, поэтому:

1. `sstp_ios_session_create(on_ready, on_packet, on_fail, self)`
2. На фоневом `NSThread`:
   - `sstp_ios_session_start(...)`
   - `sstp_ios_session_run(...)`

## Callbacks → NE

### `on_ready`

Получает `local_ip`, `gateway_ip`, `dns1`, `dns2` и вызывает:

`applyTunnelSettingsWithLocalIP:gateway:dns1:dns2:`

Настройки:

- `NEPacketTunnelNetworkSettings` с remote address = gateway
- IPv4 address = local, mask `255.255.255.255`
- `includedRoutes = defaultRoute`
- DNS servers
- `MTU = 1400`

После успешного `setTunnelNetworkSettings` → `startPacketLoop` и completionHandler(nil).

Fallbacks, если C-слой вернул NULL:

- local `10.0.0.2`
- gateway `10.0.0.1`
- DNS `8.8.8.8` / `8.8.4.4`

### `on_packet`

Пишет пакет в `packetFlow` как `AF_INET`.

### `on_fail`

Завершает pending start handler ошибкой и `cancelTunnelWithError` (domain `ru.altatec.sstp`, code `2`).

## Packet loop

`startPacketLoop`:

```text
readPacketsWithCompletionHandler
  → for each packet with AF_INET / AF_INET6
       sstp_ios_session_write_ip(session, bytes, length)
  → recurse while packetLoopRunning
```

Замечание: входящие из SSTP пишутся как `AF_INET`; исходящие AF_INET6 тоже прокидываются в C API, но туннельные settings сейчас IPv4-only.

## Stop tunnel

```objc
- (void)stopTunnelWithReason:(NEProviderStopReason)reason
           completionHandler:(void (^)(void))completionHandler
```

1. `packetLoopRunning = NO`
2. `sstp_ios_session_stop`
3. дождаться завершения worker thread
4. `sstp_ios_session_free`
5. completionHandler()

## Где править

| Задача | Место |
|--------|-------|
| MTU / routes / DNS defaults | `applyTunnelSettings...` |
| Передача credentials / Keychain ref | `startTunnelWithOptions` |
| Threading / lifecycle session | start/stop методы |
| Mapping IP packets | `startPacketLoop`, `on_packet` |

Сам протокол SSTP/PPP не здесь — см. [sstp-engine.md](sstp-engine.md).
