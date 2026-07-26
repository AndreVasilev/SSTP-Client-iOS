# Документация SSTP-Client-iOS

Документация для разработчиков и агентов. Цель — быстро понять структуру репозитория, потоки данных и точки входа для изменений.

## С чего начать

Читать по порядку:

| # | Документ | Зачем |
|---|----------|--------|
| 1 | [overview.md](overview.md) | Что это за проект, стек, границы системы |
| 2 | [architecture.md](architecture.md) | Слои, sequence connect/disconnect, поток пакетов |
| 3 | [repository-layout.md](repository-layout.md) | Карта каталогов и Xcode-таргетов |
| 4 | [app-layer.md](app-layer.md) | UI, VPNManager, Keychain |
| 5 | [tunnel-layer.md](tunnel-layer.md) | Network Extension / PacketTunnelProvider |
| 6 | [sstp-engine.md](sstp-engine.md) | C API сессии, PPP, auth/crypto |
| 7 | [build-test-ci.md](build-test-ci.md) | Сборка, тесты, CI, Fastlane |
| 8 | [agent-playbook.md](agent-playbook.md) | Куда править, типичные сценарии, ловушки |
| — | [file-index.md](file-index.md) | Короткий индекс ключевых файлов |
| — | [backlog/vpn-production-quality.md](backlog/vpn-production-quality.md) | План: ошибки, disconnect, UI sync, reconnect |
| — | [backlog/tls-certificate-verification.md](backlog/tls-certificate-verification.md) | План: TLS verify / CA / pin / trust UI |

## Быстрые якоря

- UI connect/disconnect → `com.vn.sstp/ViewController.m`, `com.vn.sstp/VPNManager.m`
- Туннель NE → `tunnel/PacketTunnelProvider.m`
- Публичный C API сессии → `sstp/sstp-ios.h`
- In-process PPP → `sstp/ios-pppd.c`
- Host unit tests → `tests/Makefile` (`make test`)
- iOS CI / TestFlight → `.github/workflows/ios-testflight.yml`, `fastlane/Fastfile`

## Важно для агентов

- Проект **нативный iOS**: Objective-C + Network Extension + C (SSTP). Не Flutter/RN.
- В Xcode **два таргета**: app `com.vn.sstp` и extension `tunnel`.
- Tunnel bundle id должен быть `$(APP_BUNDLE_ID).tunnel` — так считает `VPNManager`.
- В CI bundle id патчатся скриптом; локальные значения в `project.pbxproj` могут отличаться.
- `sstp/sstp-pppd.c` (внешний pppd) **не входит** в Sources; на iOS используется `ios-pppd.c`.
