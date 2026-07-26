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
| `connectButton` | Connect / Disconnect |
| `statusLabel` | Текст статуса VPN |
| `hintLabel` | Подсказка |
| spinner | Индикация connecting |

Строки UI сейчас на русском.

### Persistence keys

| Ключ | Хранилище |
|------|-----------|
| `sstp.server` | `NSUserDefaults` |
| `sstp.username` | `NSUserDefaults` |
| `sstp-vpn-password` | Keychain account |

## ViewController flow

1. `viewDidLoad` → build UI, load saved values, observe status, `VPNManager.reload`
2. Connect button:
   - если connected/connecting → `disconnect`
   - иначе `saveConfiguration` → `connectWithCompletion`
3. Статус обновляется по `VPNManagerStatusDidChangeNotification`

## VPNManager

Файл: `com.vn.sstp/VPNManager.m`  
Публичный API: `com.vn.sstp/VPNManager.h`

```objc
+ (instancetype)sharedManager;
- (void)reloadWithCompletion:(void (^)(NSError * _Nullable))completion;
- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                         completion:(void (^)(NSError * _Nullable))completion;
- (void)connectWithCompletion:(void (^)(NSError * _Nullable))completion;
- (void)disconnect;
```

Свойства: `status`, `statusText`, `connected`, `connecting`.

### Что делает save

- Находит/создаёт `NETunnelProviderManager` для provider bundle id = `mainBundleId + ".tunnel"`
- Пишет `NETunnelProviderProtocol`:
  - `providerBundleIdentifier`
  - `serverAddress`, `username`
  - `passwordReference` (Keychain persistent ref)
  - `disconnectOnSleep = NO`
  - `providerConfiguration = { server, username }`
- Сохраняет server/username в defaults
- Пароль в Keychain

### Что делает connect

Вызывает:

```objc
[manager.connection startVPNTunnelWithOptions:@{
  @"server": server,
  @"username": username,
  @"password": password
} completionHandler:...]
```

Важно: extension сейчас ожидает **plaintext password в start options**.  
`passwordReference` в профиле сохраняется, но в `PacketTunnelProvider` не разыменовывается.

## KeychainHelper

Файл: `com.vn.sstp/KeychainHelper.m`

- Service: `ru.altatec.sstp-client.vpn`
- Generic password items
- Методы: set / get / passwordReference / delete

## AppDelegate / SceneDelegate

- `AppDelegate.m` — lifecycle + шаблонный Core Data stack (`com_vn_sstp`)
- `SceneDelegate.m` — scene lifecycle; на background вызывает `saveContext`
- Core Data model пустой; бизнес-логика VPN его не использует

## Где править

| Задача | Файлы |
|--------|-------|
| UI / копирайт / валидация полей | `ViewController.m` |
| Логика профиля / connect options | `VPNManager.m` |
| Keychain service/account | `KeychainHelper.m` |
| Display name | `Info.plist` (`CFBundleDisplayName`) |

## Связанные документы

- Туннель → [tunnel-layer.md](tunnel-layer.md)
- Архитектура → [architecture.md](architecture.md)
