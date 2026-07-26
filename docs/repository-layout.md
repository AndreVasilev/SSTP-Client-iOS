# Карта репозитория и Xcode-таргеты

## Top-level

```text
/
├── com.vn.sstp/              # iOS app sources, assets, entitlements
├── tunnel/                   # Packet Tunnel extension
├── sstp/                     # SSTP/PPP C engine (+ iOS adaptations)
├── include/                  # Vendored OpenSSL headers
├── lib/                      # Static OpenSSL (.a)
├── libevent/                 # Vendored libevent headers + libs
├── tests/                    # Host unit tests (Linux CI)
├── scripts/                  # CI signing / pbxproj patching
├── fastlane/                 # TestFlight lane
├── .github/workflows/        # unit-tests + ios-testflight
├── com.vn.sstp.xcodeproj/    # Xcode project + shared scheme
├── docs/                     # Эта документация
├── Gemfile                   # fastlane
└── README.md                 # Краткий overview репозитория
```

## Xcode targets

Проект: `com.vn.sstp.xcodeproj`

### 1) `com.vn.sstp` (application)

- Product: `com.vn.sstp.app`
- UI + VPN profile management
- Embeds `tunnel.appex`
- Также компилирует SSTP C sources (исторически/shared), но runtime туннеля идёт через extension

### 2) `tunnel` (app extension)

- Product: `tunnel.appex`
- Principal class: `PacketTunnelProvider`
- Extension point: `com.apple.networkextension.packet-tunnel`
- Компилирует SSTP C + линкует OpenSSL/libevent/`NetworkExtension`

### Shared scheme

`com.vn.sstp.xcscheme`:

- build: tunnel + app
- run/profile: app
- testables: нет
- archive: Release

## Bundle identifiers

| Контекст | App | Tunnel |
|----------|-----|--------|
| Значения в `project.pbxproj` | `cen.com-vn-sstp` | `cen.com-vn-sstp.tunnel` |
| CI / Fastlane | `ru.altatec.sstp-client` | `ru.altatec.sstp-client.tunnel` |

Правило: tunnel id = `app id + ".tunnel"`.  
`VPNManager` вычисляет provider bundle id так же от `mainBundle.bundleIdentifier`.

CI патчит ids через `scripts/apply_bundle_ids.sh`.

## Header / library search paths

Оба таргета:

- Headers: `include/`, `libevent/include/`, `sstp/`
- Libs: `lib/`, `libevent/lib/`
- Link: `-lssl -lcrypto -levent`
- Framework: `NetworkExtension.framework`

## Entitlements

- `com.vn.sstp/com.vn.sstp.entitlements`
- `tunnel/tunnel.entitlements`

Оба содержат capability packet-tunnel Network Extension.

## Что не является runtime-путём iOS

| Путь | Заметка |
|------|---------|
| `sstp/sstp-pppd.c` | Внешний `/usr/sbin/pppd`; **не в Sources** Xcode |
| `sstp/sstp-route.c` | Linux/Apple route helpers; Apple path во многом stub |
| `sstp/sstp-dump.c` | Debug dump utilities |
| Core Data model в app | Пустой шаблон, UI не использует |

## Связанные документы

- Индекс файлов → [file-index.md](file-index.md)
- Сборка/CI → [build-test-ci.md](build-test-ci.md)
