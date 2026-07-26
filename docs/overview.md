# Обзор проекта

## Что это

**SSTP-Client-iOS** — нативное iOS-приложение для установки VPN через протокол **Microsoft SSTP** (PPP поверх HTTPS/TLS, обычно TCP/443).

Пользователь вводит сервер, логин и пароль → приложение сохраняет VPN-профиль Network Extension → extension поднимает SSTP-сессию и маршрутизирует IPv4-трафик через туннель.

## Стек

| Слой | Технологии |
|------|------------|
| UI / app | Objective-C, UIKit, programmatic UI |
| VPN API | `NetworkExtension` (`NETunnelProviderManager`, `NEPacketTunnelProvider`) |
| Протокол | C: SSTP client + in-process PPP |
| Crypto / TLS | Vendored OpenSSL 1.1.x (`libssl.a`, `libcrypto.a`) |
| Event loop | Vendored libevent 2.0.x |
| Auth | MSCHAPv2 |
| Encryption (PPP) | MPPE (RC4, 128-bit, stateless) при согласовании CCP |

## Deployment

- Минимальная iOS: **15.2** (`IPHONEOS_DEPLOYMENT_TARGET`)
- Схема Xcode: `com.vn.sstp`
- Продукты: `com.vn.sstp.app` + `tunnel.appex`

## Границы системы

**В scope приложения:**

- один экран настройки VPN;
- сохранение credentials (UserDefaults + Keychain);
- управление профилем `NETunnelProviderManager`;
- packet tunnel extension с SSTP/PPP.

**Вне scope (сейчас нет):**

- аккаунт пользователя / backend API;
- StoreKit / IAP;
- аналитика / crash SDK;
- HTTP proxy для SSTP;
- полноценный IPv6 tunnel settings;
- Xcode UI-тесты.

## Версии зависимостей (vendored)

- OpenSSL headers: `include/openssl/opensslv.h` → **1.1.0f**
- libevent headers: `libevent/include/...` → **2.0.22-stable**
- Package string в `sstp/config.h`: `sstp-client-ios 1.0.0`

## Связанные документы

- Архитектура и потоки → [architecture.md](architecture.md)
- Карта репозитория → [repository-layout.md](repository-layout.md)
