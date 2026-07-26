# Индекс ключевых файлов

Короткие однострочники для навигации. Пути от корня репозитория.

## App

| Файл | Назначение |
|------|------------|
| `com.vn.sstp/ViewController.m` | Programmatic UI, connect/disconnect |
| `com.vn.sstp/VPNManager.h` | Публичный API менеджера VPN |
| `com.vn.sstp/VPNManager.m` | NETunnelProviderManager, start options, status |
| `com.vn.sstp/KeychainHelper.m` | Generic password Keychain wrapper |
| `com.vn.sstp/AppDelegate.m` | App lifecycle + шаблонный Core Data |
| `com.vn.sstp/SceneDelegate.m` | Scene lifecycle |
| `com.vn.sstp/Info.plist` | Display name, scene manifest |
| `com.vn.sstp/com.vn.sstp.entitlements` | Network Extension entitlement |
| `shared/SSTPShared.h` | App ↔ tunnel constants / error UI helpers |
| `com.vn.sstp/Base.lproj/Main.storyboard` | Root scene → ViewController |
| `com.vn.sstp/Base.lproj/LaunchScreen.storyboard` | Launch screen |
| `com.vn.sstp/Assets.xcassets/AppIcon.appiconset/` | App icons |

## Tunnel

| Файл | Назначение |
|------|------------|
| `tunnel/PacketTunnelProvider.m` | NE entry: start/stop, settings, reconnect, status IPC |
| `tunnel/PacketTunnelProvider.h` | Provider interface |
| `tunnel/Info.plist` | Extension point + principal class |
| `tunnel/tunnel.entitlements` | Network Extension entitlement |
| `tunnel/cacert.pem` | Bundled CA roots for OpenSSL verify |

## SSTP engine

| Файл | Назначение |
|------|------------|
| `sstp/sstp-ios.h` | Публичный C API iOS-сессии |
| `sstp/sstp-ios-error.h` | Стабильные stage/error codes |
| `sstp/sstp-ios-error.c` | Fatal/valid helpers for codes/stages |
| `sstp/sstp-ios.c` | Lifecycle сессии, TLS trust, stages, event-loop glue |
| `sstp/ios-pppd.c` | In-process PPP/MSCHAPv2/IPCP/MPPE |
| `sstp/sstp-mschapv2.c` | MSCHAPv2 / MPPE crypto helpers |
| `sstp/sstp-mschapv2.h` | Headers helpers |
| `sstp/sstp-state.c` | SSTP control state machine / crypto binding |
| `sstp/sstp-stream.c` | OpenSSL + libevent stream |
| `sstp/sstp-http.c` | HTTP SSTP handshake |
| `sstp/sstp-packet.c` | SSTP packet encode/decode |
| `sstp/sstp-cmac.c` | CMAC / binding helpers |
| `sstp/sstp-chap.c` | CHAP/MPPE key derivation helpers |
| `sstp/sstp-buff.c` | Buffer helpers |
| `sstp/sstp-fcs.c` | PPP/HDLC FCS |
| `sstp/sstp-option.c` | Options / URL option plumbing |
| `sstp/sstp-util.c` | Utilities including URL parse |
| `sstp/sstp-client.c` | Original client orchestration |
| `sstp/sstp-pppd.c` | External pppd integration (**не в Xcode Sources**) |
| `sstp/config.h` | iOS compile-time feature config |
| `sstp/sstp-private.h` | Internal shared types/decls |

## Project / build

| Файл | Назначение |
|------|------------|
| `com.vn.sstp.xcodeproj/project.pbxproj` | Targets, sources, ids, search paths, signing |
| `com.vn.sstp.xcodeproj/xcshareddata/xcschemes/com.vn.sstp.xcscheme` | Shared scheme |
| `Gemfile` | Fastlane gem |
| `fastlane/Fastfile` | `ios beta` lane |
| `fastlane/Appfile` | App Store Connect app id |
| `scripts/prepare_ios_signing.sh` | CI cert/profile/keychain setup |
| `scripts/apply_bundle_ids.sh` | CI patch bundle ids / signing / build number |
| `.github/workflows/unit-tests.yml` | Host `make test` |
| `.github/workflows/ios-testflight.yml` | macOS build + TestFlight |

## Tests

| Файл | Назначение |
|------|------------|
| `tests/Makefile` | Build/run host unit tests |
| `tests/harness.h` | Tiny assert/report helpers |
| `tests/test_mschapv2.c` | MSCHAPv2 vectors |
| `tests/test_fcs.c` | FCS roundtrip |
| `tests/test_buff.c` | Buffer helper tests |
| `tests/test_url.c` | URL parser tests |
| `tests/test_ios_error.c` | Error/stage contract mapping |
| `tests/test_cert_host.c` | SAN/wildcard/CN hostname helpers |
| `tests/stubs/` | Stub headers for host builds |

## Docs

| Файл | Назначение |
|------|------------|
| `docs/README.md` | Оглавление и быстрые якоря |
| `docs/overview.md` | Что за проект |
| `docs/architecture.md` | Слои и sequence |
| `docs/repository-layout.md` | Каталоги и таргеты |
| `docs/app-layer.md` | UI / VPNManager |
| `docs/tunnel-layer.md` | Packet tunnel |
| `docs/sstp-engine.md` | C engine |
| `docs/build-test-ci.md` | Сборка и CI |
| `docs/agent-playbook.md` | Куда править / ловушки |
| `docs/file-index.md` | Этот файл |
| `docs/backlog/vpn-production-quality.md` | План доработок production-качества VPN |
| `docs/backlog/tls-certificate-verification.md` | План: проверка TLS-сертификата сервера |
