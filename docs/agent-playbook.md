# Agent playbook

Практические правила для изменений в репозитории.

## Карта «хочу изменить X → иду в Y»

| Задача | Куда |
|--------|------|
| Текст/валидация UI, кнопка Connect | `com.vn.sstp/ViewController.m` |
| Сохранение профиля, start options, статус | `com.vn.sstp/VPNManager.m` |
| Keychain service/account | `com.vn.sstp/KeychainHelper.m` |
| MTU, routes, DNS, packet loop | `tunnel/PacketTunnelProvider.m` |
| Session API / TLS connect / event loop glue | `sstp/sstp-ios.c`, `sstp/sstp-ios.h` |
| PPP / MSCHAPv2 exchange / MPPE frames | `sstp/ios-pppd.c` |
| Crypto helpers MSCHAPv2 | `sstp/sstp-mschapv2.c` + `tests/test_mschapv2.c` |
| SSTP control / crypto binding | `sstp/sstp-state.c`, `sstp/sstp-packet.c`, `sstp/sstp-cmac.c` |
| HTTP handshake | `sstp/sstp-http.c` |
| Stream/TLS low-level | `sstp/sstp-stream.c` |
| Host unit tests | `tests/*`, `tests/Makefile` |
| CI TestFlight / signing | `.github/workflows/ios-testflight.yml`, `scripts/*`, `fastlane/*` |
| Bundle id / signing в pbxproj | `com.vn.sstp.xcodeproj/project.pbxproj` (+ помнить про CI patch) |

## Обязательные инварианты

1. **Tunnel bundle id = app bundle id + `.tunnel`**  
   Ломается connect, если ids разъедутся (см. `VPNManager`).

2. **Пароль в start options**  
   Extension сейчас читает `options[@"password"]`, не Keychain reference. Меняя один конец — синхронизируй другой.

3. **Не возвращай `sstp-pppd.c` в Sources для iOS**  
   На устройстве нет внешнего pppd. Используется `ios-pppd.c`.

4. **SSTP C sources в двух таргетах**  
   Правка `.c` в `sstp/` влияет на app и tunnel build phases. Проверяй оба, если меняешь project membership.

5. **Host tests ≠ iOS runtime**  
   `tests/` линкуют system OpenSSL и stubs. Успешный `make test` не доказывает, что extension поднимется на девайсе.

6. **OpenSSL API 1.1.x**  
   Vendored headers — 1.1.0f. Не писать код только под 3.x API без проверки.

## Типичные сценарии работы агента

### A. Починить connect UI / статус

1. Прочитать `ViewController.m` + `VPNManager.m`
2. Проверить notification и mapping `NEVPNStatus` → текст кнопки
3. Не трогать C engine без нужды

### B. Починить «туннель не стартует»

1. `VPNManager` start options / bundle id
2. `PacketTunnelProvider.startTunnelWithOptions` — есть ли password
3. Логи fail callback (`on_fail`)
4. Затем `sstp_ios_session_start` / TLS / HTTP

### C. Починить auth / IP assign

1. `ios-pppd.c` (LCP/CHAP/IPCP)
2. `sstp-mschapv2.c` + unit test
3. `sstp-ios.c` PPP callbacks (`SSTP_PPP_AUTH`, `SSTP_PPP_UP`)
4. `sstp-state.c` accept / crypto binding

### D. Добавить host-тест

1. Новый `tests/test_*.c` + harness
2. Подключить target в `tests/Makefile`
3. Если нужен SSTP `.c`, учесть трюк с `build/` copy + `stubs/`

### E. Изменить CI identifiers / build number

1. Env в `ios-testflight.yml`
2. Логика патча в `scripts/apply_bundle_ids.sh`
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

## Известные TODO в коде (неполный список)

- `sstp/sstp-route.c` — Apple route helpers во многом stub (`TODO`, return `-1`)
- `sstp/sstp-option.c` — закомментированы default privilege/CA path assignments
- `sstp/sstp-client.c` — TODO про runtime directory
- `sstp/sstp-pppd.c` — EAP TLS не поддержан в том режиме (файл не в iOS Sources)
- Root `README.md` помечает проект как incomplete version

## Связанные документы

- Индекс файлов → [file-index.md](file-index.md)
- Engine details → [sstp-engine.md](sstp-engine.md)
