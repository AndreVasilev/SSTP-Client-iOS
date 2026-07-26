# App layer

Код контейнерного приложения: UI, сохранение credentials, управление VPN-профилем.

## Точка входа UI

- Storyboard: `com.vn.sstp/Base.lproj/Main.storyboard` → сцена `ViewController`
- Фактический UI строится **программно** в `com.vn.sstp/ViewController.m`

### Поля экрана

| UI | Назначение |
|----|------------|
| `brandLabel` / `subtitleLabel` | Заголовки |
| `serverField` | Хост VPN |
| `usernameField` | Логин |
| `passwordField` | Пароль |
| TLS mode / CA PEM / pin | Доверие сертификату (`system` / `custom_ca` / `pinned`) |
| `connectButton` | Connect / Disconnect |
| `statusLabel` | Статус + стадия / причина ошибки |
| `hintLabel` | Подсказка next-step |
| spinner | Индикация connecting |

Строки UI на русском.

### Persistence keys

| Ключ | Хранилище |
|------|-----------|
| `sstp.server` | `NSUserDefaults` |
| `sstp.username` | `NSUserDefaults` |
| `sstp.tlsMode` / `sstp.caPem` / `sstp.pinSha256` | `NSUserDefaults` |
| `sstp-vpn-password` | Keychain account |

## ViewController flow

1. `viewDidLoad` → build UI, load saved values, observe status, `VPNManager.reload`
2. Connect button:
   - если connected/connecting → `disconnect`
   - иначе `saveConfiguration` (с TLS mode) → `connectWithCompletion`
3. Статус обновляется по `VPNManagerStatusDidChangeNotification`
4. После fail показывается локализованный hint по `lastErrorCode` (не generic «Отключено»)

## VPNManager

Файл: `com.vn.sstp/VPNManager.m`  
Публичный API: `com.vn.sstp/VPNManager.h`

Свойства: `status`, `statusText`, `connected`, `connecting`, `stage`, `lastErrorCode`, `lastErrorMessage`, `lastErrorHint`.

### save / connect

- `providerConfiguration` включает `tlsMode`, опционально `caPem` / `pinSha256`
- Connect options передают plaintext password **и** TLS config
- Старт из Settings без options работает через `passwordReference` в extension
- На `NEVPNStatusDidChange` запрашивается `get_status` у session; при Disconnected читается App Group last error
- Double-tap Connect защищён флагом `connectRequested`

## Shared contract

`shared/SSTPShared.h` — App Group id (`group.<appBundleId>`), error domain, JSON message keys, UI copy для stage/code.

Entitlements (app + tunnel):

- `com.apple.security.application-groups`
- `keychain-access-groups` (общий доступ к password reference)
- CI script `scripts/apply_bundle_ids.sh` патчит App Group под `APP_BUNDLE_ID`

## KeychainHelper

Файл: `com.vn.sstp/KeychainHelper.m`

- Service: `ru.altatec.sstp-client.vpn`
- Accessible: `AfterFirstUnlockThisDeviceOnly`
- Методы: set / get / passwordReference / delete

## Где править

| Задача | Файлы |
|--------|-------|
| UI / копирайт / валидация полей | `ViewController.m` |
| Логика профиля / connect options / status sync | `VPNManager.m` |
| Shared strings / App Group helpers | `shared/SSTPShared.h` |
| Keychain service/account | `KeychainHelper.m` |

## Связанные документы

- Туннель → [tunnel-layer.md](tunnel-layer.md)
- Архитектура → [architecture.md](architecture.md)
