# Сборка, тесты, CI

## Локальная iOS-сборка (Xcode)

1. Открыть `com.vn.sstp.xcodeproj`
2. Scheme: `com.vn.sstp`
3. Нужна валидная подпись + Network Extension capability для пары app/tunnel
4. Bundle id туннеля должен быть `$(APP_ID).tunnel`

Deployment target: **iOS 15.2**.

Зависимости уже vendored:

- `include/` + `lib/` → OpenSSL
- `libevent/include/` + `libevent/lib/` → libevent

Ruby/Fastlane (опционально локально):

```sh
bundle install
bundle exec fastlane ios beta   # требует secrets / signing
```

## Host unit tests

Каталог: `tests/`

```sh
cd tests
make test
# make clean
```

Требования на Linux:

- `build-essential`
- `libssl-dev` (system OpenSSL; iOS `.a` не используются)
- `pkg-config` (в CI)

Бинарники:

| Тест | Что покрывает |
|------|----------------|
| `test_mschapv2` | MSCHAPv2 / MPPE helpers (`sstp-mschapv2.c`) |
| `test_fcs` | FCS encode/decode (`sstp-fcs.c`) |
| `test_buff` | buffer helpers (`sstp-buff.c`) |
| `test_url` | URL parse (`sstp-util.c`) |

Особенность Makefile: исходники копируются в `tests/build/`, а `#include "sstp-private.h"` резолвится через `tests/stubs/`, чтобы не тянуть полный iOS/libevent private header.

Xcode testables в scheme **нет**.

## GitHub Actions

### `unit-tests.yml`

- Triggers: push `main` / `cursor/**`, PR, `workflow_dispatch`
- Runner: Ubuntu
- Команда: `make test` в `tests/`

### `ios-testflight.yml`

- Triggers: push `main`, `workflow_dispatch`, schedule (каждые 80 дней)
- Runner: `macos-26`
- Расписание: cron `0 6 * * *` (ежедневная проверка в 06:00 UTC); сборка запускается, когда `(unix_day % 80) == 0`
- Env:
  - `APP_BUNDLE_ID=ru.altatec.sstp-client`
  - `TUNNEL_BUNDLE_ID=ru.altatec.sstp-client.tunnel`
  - `BUILD_NUMBER=${{ github.run_number }}`
- Шаги:
  1. выбрать Xcode 26.x при наличии
  2. Ruby 3.3 + bundler
  3. `scripts/prepare_ios_signing.sh`
  4. `scripts/apply_bundle_ids.sh`
  5. `bundle exec fastlane ios beta`
  6. upload `build/*.ipa` artifact

## Fastlane

`fastlane/Fastfile` → lane `ios beta`:

- scheme `com.vn.sstp`
- project `com.vn.sstp.xcodeproj`
- identifiers: `ru.altatec.sstp-client` (+ `.tunnel`)
- `build_app` (Release, clean, manual signing) → `build/sstp-client`
- `upload_to_testflight`

`fastlane/Appfile`: `app_identifier("ru.altatec.sstp-client")`

Ожидаемые secrets/env (через CI):

- App Store Connect API key JSON (`ALTATEC_APPSTORECONNECT_API_KEY`)
- certificate / provisioning profiles (см. `prepare_ios_signing.sh`)

## Scripts

| Script | Назначение |
|--------|------------|
| `scripts/prepare_ios_signing.sh` | Импорт cert/profiles, temp keychain, export team/profile env |
| `scripts/apply_bundle_ids.sh` | Патч `project.pbxproj`: bundle ids, build number, manual signing, profiles |

## Версионирование

В проекте:

- `MARKETING_VERSION = 1.0`
- `CURRENT_PROJECT_VERSION = 1`

CI переписывает `CURRENT_PROJECT_VERSION` на `github.run_number`.

## Связанные документы

- Таргеты/ids → [repository-layout.md](repository-layout.md)
- Playbook агента → [agent-playbook.md](agent-playbook.md)
