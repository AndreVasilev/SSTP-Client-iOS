## Summary

Довести VPN-клиент до production-качества: предсказуемые ошибки, корректный disconnect, синхронизация UI ↔ VPN, базовый reconnect для transient-сбоев.

Сейчас в основном закрыт happy path. Fail-path обрывается в extension (`cancelTunnelWithError`) и почти не доходит до осмысленного UX в приложении.

## Current state (as-is)

### App (`ViewController` / `VPNManager`)
- UI опирается только на грубый `NEVPNStatus` (Invalid / Disconnected / Connecting / Connected / Reasserting / Disconnecting).
- `connectWithCompletion` получает успех на этапе «iOS принял `startVPNTunnel`», а не «SSTP-сессия поднята».
- После падения туннеля пользователь чаще видит просто «Отключено», без причины.
- Нет last error / connect stage, которые переживают цикл Connecting → Disconnected.

### Extension (`PacketTunnelProvider`)
- Fail сводится к `NSError` domain `ru.altatec.sstp`, code `2` + строка.
- `handleAppMessage` пустой — app не может запросить статус/ошибку у extension.
- Password ожидается в start options; `passwordReference` не разыменовывается (старт из Settings / без options ломается).
- Stop: busy-wait по `worker.isFinished` без жёсткого timeout.

### C engine (`sstp-ios.c` / `ios-pppd.c`)
- Есть текстовые `sstp_ios_fail("...")` (DNS / TLS / HTTP / PPP / crypto binding), но без стабильных кодов и стадий.
- Нет классификации fatal vs transient.
- Нет API для reconnect / staged progress.

## Goals

1. Пользователь всегда понимает **на каком шаге** и **почему** connect не удался.
2. Disconnect быстрый, идемпотентный, без zombie session/thread.
3. UI не врёт после «успешного» start и синхронизирован с реальным состоянием туннеля.
4. Transient-сбои (сеть, timeout) могут автоматически переподключаться; fatal (auth, bad cert policy) — нет.

## Non-goals (этот issue)

- IPv6 dual-stack / HTTP proxy.
- Полный rewrite SSTP-стека.
- Analytics/crash SDK (можно отдельно).
- UI redesign beyond status/error surfaces.

---

## Proposed error / stage model

### Stages
```
idle
resolving
tcp_tls
http_upgrade
sstp_control
ppp_lcp
ppp_auth
ppp_ipcp
ppp_mppe
applying_settings
connected
disconnecting
reconnecting
error
```

### Error codes (stable, machine-readable)
```
dns_resolve
tcp_timeout
tls_handshake
tls_cert
http_upgrade
sstp_control
auth_rejected
ipcp_failed
crypto_binding
mppe_failed
network_lost
missing_credentials
cancelled
internal
```

Каждая ошибка: `code` + `stage` + короткий `message` (для UI/логов, без паролей/токенов).

### Fatal vs transient
| Code | Class | Auto-reconnect |
|------|-------|----------------|
| `auth_rejected`, `missing_credentials`, `tls_cert` (если policy = reject), `cancelled` | fatal | no |
| `dns_resolve`, `tcp_timeout`, `tls_handshake`, `network_lost`, часть `sstp_control`/`http_upgrade` | transient | yes (limited) |

---

## Implementation plan

### Phase 0 — Контракт между слоями
**Files:** `sstp/sstp-ios.h`, возможно новый `sstp/sstp-ios-error.h`

- Расширить C API: staged callback и/или last error struct.
- Пример направления API:
  - `sstp_ios_status_fn(ctx, stage)`
  - `sstp_ios_fail_fn(ctx, code, stage, message)` (вместо одной строки)
- Зафиксировать enum/string codes, общие для C / ObjC.

**Acceptance:** tunnel и app используют один словарь кодов; unit-тест/табличный smoke на маппинг.

### Phase 1 — C engine: коды и стадии
**Files:** `sstp/sstp-ios.c`, `sstp/ios-pppd.c` (+ headers)

- Заменить «голые» `sstp_ios_fail("Could not resolve...")` на `(code, stage, message)`.
- Проставить stage transitions в lifecycle:
  - resolve → tcp/tls → http → sstp → ppp_* → ready
- На `SSTP_PPP_AUTH` fail / CHAP reject → `auth_rejected` (fatal).
- На resolve/connect timeout → `dns_resolve` / `tcp_timeout` (transient).
- Crypto binding fail → `crypto_binding`.
- Не логировать plaintext password.

**Acceptance:** искусственные fail-path в debug дают ожидаемые codes; существующий happy path не регрессит.

### Phase 2 — Extension: ошибки, stop, credentials
**Files:** `tunnel/PacketTunnelProvider.m`

1. **Map C errors → `NSError`**
   - domain `ru.altatec.sstp` (или новый стабильный)
   - `code` numeric + `userInfo` с `code`/`stage`/`NSLocalizedDescriptionKey`
2. **Last error persistence**
   - App Group UserDefaults / файл, либо ответ на `handleAppMessage`
   - Писать last error перед `cancelTunnelWithError`
3. **Provider messages**
   - Реализовать `handleAppMessage`:
     - `get_status` → `{ stage, connected, lastError }`
4. **Credentials**
   - Разыменовывать `passwordReference`, если options password пуст
   - Ошибка `missing_credentials`, если оба пути пусты
5. **Stop hardening**
   - Timeout ожидания worker (например 2–5s), затем принудительный cleanup
   - Защита от callback’ов после teardown (generation token / session NULL checks)
   - Не вызывать start completion дважды

**Acceptance:**
- stop всегда завершает `completionHandler`;
- bad password даёт `auth_rejected` в last error;
- старт без options, но с Keychain ref — работает.

### Phase 3 — App: UI ↔ VPN sync + last error
**Files:** `com.vn.sstp/VPNManager.m/.h`, `com.vn.sstp/ViewController.m`, entitlements/App Group если нужно

1. Расширить состояние VPNManager:
   - `stage`, `lastError`, возможно `connectionState` поверх `NEVPNStatus`
2. На каждый `NEVPNStatusDidChange`:
   - обновить status;
   - запросить у session `get_status` / прочитать App Group last error
3. UI:
   - status line = stage-aware («TLS…», «Аутентификация…», «Подключено»)
   - при Disconnected после fail показывать человекочитаемую причину + next step
   - не оставлять hint «если iOS спросит разрешение» после fail
4. Развести:
   - ошибка save profile;
   - ошибка startVPNTunnel API;
   - ошибка runtime tunnel

**Acceptance:**
- fail auth → UI явно про логин/пароль;
- fail DNS → UI про сервер/сеть;
- success path по-прежнему показывает Connected.

### Phase 4 — Reconnect (transient only)
**Files:** `tunnel/PacketTunnelProvider.m`, опционально `sstp-ios.c`

- Policy: max N attempts, exponential backoff (например 1s / 2s / 5s), jitter optional.
- Reconnect только для transient codes.
- Не reconnect после явного user disconnect / fatal errors.
- UI: stage `reconnecting(attempt/max)` через тот же status channel.
- Уважать `NEVPNStatusReasserting`, если система сама инициирует reassert — не дублировать хаотично.

**Acceptance:**
- краткий network blip → восстановление без ручного tap;
- неверный пароль → без retry loop;
- Disconnect пользователем → остаётся Disconnected.

### Phase 5 — Hardening & verification
- Логи: stage/code only, redact secrets.
- Ручной test matrix (ниже).
- По возможности: host-level tests на маппинг кодов; document manual NE tests.
- Обновить `docs/sstp-engine.md`, `docs/tunnel-layer.md`, `docs/app-layer.md`, `docs/agent-playbook.md` под новый контракт.

---

## Suggested file touch list

| Area | Files |
|------|-------|
| C API | `sstp/sstp-ios.h`, `sstp/sstp-ios.c`, maybe `sstp/sstp-ios-error.h` |
| PPP | `sstp/ios-pppd.c` |
| Tunnel | `tunnel/PacketTunnelProvider.m` |
| App | `com.vn.sstp/VPNManager.h`, `VPNManager.m`, `ViewController.m` |
| Shared container | app + tunnel entitlements / App Group id |
| Docs | `docs/architecture.md`, `docs/sstp-engine.md`, `docs/tunnel-layer.md`, `docs/app-layer.md`, `docs/agent-playbook.md` |

## Manual test matrix

| Scenario | Expected |
|----------|----------|
| Valid server/user/pass | stages → Connected; traffic works |
| Bad DNS hostname | error `dns_resolve`; UI explains |
| TLS timeout / closed port | `tcp_timeout` or `tls_handshake` |
| Wrong password | `auth_rejected`; no reconnect loop |
| User disconnect while connecting | clean Disconnecting → Disconnected; no zombie |
| Kill network briefly while connected | reconnect attempts then recover or clear error |
| Start from system VPN toggle with saved profile | password via Keychain ref works |
| Double-tap Connect | no double session / no stuck Connecting |
| Stop under load | stop completes within timeout |

## Rollout order

1. Phase 0–1 (contract + C codes) — можно завести/мержить отдельно, UI ещё старый.
2. Phase 2 (extension last error + stop/credentials) — разблокирует диагностику.
3. Phase 3 (UI sync) — пользовательский эффект.
4. Phase 4 (reconnect) — только после стабильных codes/fatal classification.
5. Phase 5 (docs + matrix).

## Open questions

- App Group id / team prefix для shared last error?
- Нужен ли user-visible detailed log screen или только hint/status?
- Cert policy: leave-as-warn (`SSTP_OPT_CERTWARN`) или fatal `tls_cert`? Влияет на fatal/transient.  
  Вынесено в отдельный backlog: [tls-certificate-verification.md](tls-certificate-verification.md) (strict verify by default + CA/pin).
- Max reconnect attempts / backoff — выбрать дефолты до реализации Phase 4.
