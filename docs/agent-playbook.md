# Agent playbook

Практические правила для изменений в репозитории.

## Карта «хочу изменить X → иду в Y»

| Задача | Куда |
|--------|------|
| Текст/валидация UI, кнопка Connect | `com.vn.sstp/ViewController.m` |
| Сохранение профиля, start options, статус / last error | `com.vn.sstp/VPNManager.m` |
| Keychain service/account | `com.vn.sstp/KeychainHelper.m` |
| Shared App Group / error UI copy | `shared/SSTPShared.h` |
| MTU, routes, DNS, packet loop, reconnect | `tunnel/PacketTunnelProvider.m` |
| Session API / TLS connect / stages / errors | `sstp/sstp-ios.c`, `sstp/sstp-ios.h`, `sstp/sstp-ios-error.*` |
| PPP / MSCHAPv2 exchange / MPPE frames | `sstp/ios-pppd.c` |
| Crypto helpers MSCHAPv2 | `sstp/sstp-mschapv2.c` + `tests/test_mschapv2.c` |
| SSTP control / crypto binding | `sstp/sstp-state.c`, `sstp/sstp-packet.c`, `sstp/sstp-cmac.c` |
| HTTP handshake | `sstp/sstp-http.c` |
| Stream/TLS / hostname verify | `sstp/sstp-stream.c` |
| CA bundle for NE | `tunnel/cacert.pem` |
| Host unit tests | `tests/*`, `tests/Makefile` |
| CI TestFlight / signing / App Group patch | `.github/workflows/ios-testflight.yml`, `scripts/*`, `fastlane/*` |
| Bundle id / signing в pbxproj | `com.vn.sstp.xcodeproj/project.pbxproj` (+ помнить про CI patch) |

## Обязательные инварианты

1. **Tunnel bundle id = app bundle id + `.tunnel`**  
   Ломается connect, если ids разъедутся (см. `VPNManager`).

2. **Пароль: options и/или passwordReference**  
   Extension читает `options[@"password"]`, иначе разыменовывает `passwordReference`.  
   Не добавляй App Groups / лишние entitlements без обновления provisioning profiles — CI App Store profiles сейчас содержат только NE.

3. **Не возвращай `sstp-pppd.c` в Sources для iOS**  
   На устройстве нет внешнего pppd. Используется `ios-pppd.c`.

4. **SSTP C sources в двух таргетах**  
   Правка `.c` в `sstp/` влияет на app и tunnel build phases. Проверяй оба, если меняешь project membership.  
   Не забудь `sstp-ios-error.c`.

5. **Host tests ≠ iOS runtime**  
   `tests/` линкуют system OpenSSL и stubs. Успешный `make test` не доказывает, что extension поднимется на девайсе.

6. **OpenSSL API 1.1.x**  
   Vendored headers — 1.1.0f. Не писать код только под 3.x API без проверки.

7. **TLS verify on by default**  
   Production path: `SSL_VERIFY_PEER` + chain/hostname; fail → `tls_cert` (fatal, no reconnect).  
   Self-signed → `custom_ca` или `pinned`, не `INSECURE_DEBUG` в Release.

## Trust modes (TLS)

| Mode | Когда |
|------|-------|
| `system` | Default; bundled `cacert.pem` + hostname |
| `custom_ca` | Корпоративный/lab CA (PEM в UI) |
| `pinned` | SHA-256 leaf pin (64 hex) |
| `insecure_debug` | Только Debug builds |

## Error / stage contract

См. `sstp/sstp-ios-error.h`. App показывает stage-aware status и hint по code.  
Transient → limited reconnect в extension; fatal → сразу Disconnected с причиной.

## Типичные сценарии работы агента

### A. Починить connect UI / статус

1. Прочитать `ViewController.m` + `VPNManager.m`
2. Проверить notification, `get_status`, App Group last error
3. Не трогать C engine без нужды

### B. Починить «туннель не стартует»

1. `VPNManager` start options / bundle id / TLS config
2. `PacketTunnelProvider.startTunnelWithOptions` — password / passwordReference
3. Логи fail callback (`on_fail` code/stage)
4. Затем `sstp_ios_session_start_ex` / TLS / HTTP

### C. Починить auth / IP assign

1. `ios-pppd.c` (LCP/CHAP/IPCP) — `SSTP_PPP_AUTH_FAIL`
2. `sstp-mschapv2.c` + unit test
3. `sstp-ios.c` PPP callbacks
4. `sstp-state.c` accept / crypto binding

### D. Добавить host-тест

1. Новый `tests/test_*.c` + harness
2. Подключить target в `tests/Makefile`
3. Если нужен SSTP `.c`, учесть трюк с `build/` copy + `stubs/`

### E. Изменить CI identifiers / build number

1. Env в `ios-testflight.yml`
2. Логика патча в `scripts/apply_bundle_ids.sh` (bundle id **и** App Group entitlements)
3. Константы в `fastlane/Fastfile` / `Appfile`

## Что обычно не нужно трогать

- Vendored деревья `include/openssl/**`, `lib/**`, `libevent/**` — только при осознанном обновлении зависимостей
- Пустой Core Data stack в `AppDelegate` — не часть VPN-потока
- `sstp-route.c` / `sstp-dump.c` / `sstp-task.c` — периферия Linux-клиента

## Порядок чтения при холодном старте

1. `docs/README.md`
2. `docs/overview.md` + `docs/architecture.md`
3. `ViewController.m` → `VPNManager.m` → `PacketTunnelProvider.m` → `sstp-ios.h` / `sstp-ios.c`
4. При задаче по PPP/crypto — `ios-pppd.c`, `sstp-mschapv2.c`
5. При задаче по CI — `build-test-ci.md`

## Связанные документы

- Индекс файлов → [file-index.md](file-index.md)
- Engine details → [sstp-engine.md](sstp-engine.md)
- Production backlog (done) → [backlog/vpn-production-quality.md](backlog/vpn-production-quality.md)
- TLS backlog (done) → [backlog/tls-certificate-verification.md](backlog/tls-certificate-verification.md)
