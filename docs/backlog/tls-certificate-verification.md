# Backlog: TLS certificate verification

## Summary

Сейчас TLS-проверка сертификата сервера фактически отключена. Для VPN это неприемлемо: нужен обязательный verify по умолчанию и опциональный путь для self-signed (pin / trust UI).

Связанный, но отдельный трек: [vpn-production-quality.md](vpn-production-quality.md) (маппинг ошибки `tls_cert` в UI). Этот документ — про **включение и политику проверки**, не про reconnect/UI sync в целом.

## Current state (as-is)

### OpenSSL verify mode
В `sstp/sstp-ios.c` → `ios_init_ssl()`:

```c
SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_NONE, NULL);
```

Peer certificate **не валидируется** OpenSSL во время handshake.

### Post-handshake check ослаблен
После HTTP handshake вызывается `sstp_verify_cert` только с `SSTP_VERIFY_NAME` (сравнение CN/host), **без** `SSTP_VERIFY_CERT` (chain / `SSL_get_verify_result`).

При fail:

```c
log_warn("Server certificate verification failed, continuing");
```

Соединение продолжается.

### CERTWARN всегда включён
В `sstp_ios_session_start`:

```c
opt->enable = ... | SSTP_OPT_CERTWARN | ...
```

На Linux-пути в `sstp-client.c` при отсутствии `CERTWARN` verify fail останавливает сессию; на iOS warn+continue зашит.

### CA store не подключается на iOS
В оригинальном `sstp-client.c` при `ca_cert` / `ca_path` вызывается `SSL_CTX_load_verify_locations` и включается `SSTP_VERIFY_CERT`.  
В iOS session path этого нет: ни system roots, ни custom CA.

### Ограничения текущего `sstp_verify_cert`
`sstp-stream.c` name check — через subject CN (`X509_NAME_get_text_by_NID`), без нормального SAN / wildcard handling. Даже после «включения» name verify нужна доработка под современные сертификаты.

## Risk

Без chain verify + hostname verify VPN уязвим к MITM на пути до SSTP-сервера (поддельный TLS endpoint). Crypto binding SSTP защищает другой класс атак и **не заменяет** TLS authentication сервера.

## Goals

1. По умолчанию: **reject** при невалидной цепочке или hostname mismatch.
2. Подключить trust store (system roots и/или явный CA).
3. Дать явный opt-in для lab/self-signed: pin fingerprint **или** user trust decision в UI.
4. Пробрасывать fail как стабильный код `tls_cert` (см. production-quality backlog).
5. Не логировать секреты; в UI — понятная причина.

## Non-goals

- Полная замена OpenSSL на Network.framework TLS (можно later).
- Client certificate (mTLS) auth — отдельный epic.
- Certificate transparency / OCSP stapling как must-have v1 (можно phase 2).
- Export compliance / App Store paperwork.

---

## Proposed trust policy

### Default (production)
```
verify mode: SSL_VERIFY_PEER (+ fail if no peer cert)
trust anchors: system CA store (or bundled Mozilla/Apple-compatible roots if system path unavailable in NE)
checks: chain + hostname (SAN/CN) + expiry
on failure: abort session → error code tls_cert (fatal, no reconnect)
```

### Optional profiles (explicit user/config choice)

| Profile | Behavior |
|---------|----------|
| `system` (default) | System/bundled roots, strict hostname |
| `custom_ca` | User-provided CA PEM/DER in app config / Keychain |
| `pinned` | SPKI/SHA-256 pin of leaf or intermediate; still require valid dates unless overridden |
| `insecure_debug` | Only Debug builds / hidden developer switch; never default in Release |

Self-signed corporate VPN → `custom_ca` или `pinned`, не «просто выключить verify».

---

## Implementation plan

### Phase 0 — Audit & API contract
**Files:** `sstp/sstp-ios.h`, maybe `sstp/sstp-ios-tls.h`

Зафиксировать параметры сессии:

```c
typedef enum {
  SSTP_IOS_TLS_SYSTEM = 0,
  SSTP_IOS_TLS_CUSTOM_CA = 1,
  SSTP_IOS_TLS_PINNED = 2,
  SSTP_IOS_TLS_INSECURE_DEBUG = 3  /* Debug only */
} sstp_ios_tls_mode_t;

// start API gains tls mode + optional ca_pem / pin_sha256
```

Согласовать с extension/app: откуда читается mode (providerConfiguration / App Group).

**Acceptance:** документ + header contract; поведение ещё может быть stub.

### Phase 1 — Enable real OpenSSL verify on iOS path
**Files:** `sstp/sstp-ios.c`, возможно `sstp/sstp-stream.c`

1. Заменить `SSL_VERIFY_NONE` → `SSL_VERIFY_PEER` (и `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` где уместно).
2. Загрузить trust anchors:
   - предпочтительно system CA path / iOS-accessible roots strategy for OpenSSL 1.1.x in NE;
   - если system path в Network Extension недоступен — bundled CA bundle + update process.
3. Убрать безусловный `SSTP_OPT_CERTWARN` из iOS default enable mask.
4. После connect вызывать `sstp_verify_cert` с `SSTP_VERIFY_CERT | SSTP_VERIFY_NAME`.
5. Fail → abort (`tls_cert`), **не** `log_warn` + continue.

**Acceptance:**
- публичный Let's Encrypt / публичный CA сервер → connect OK;
- mitm-like bad cert / wrong host → session fails before PPP;
- Release default никогда не продолжает при verify fail.

### Phase 2 — Hostname / SAN verification upgrade
**Files:** `sstp/sstp-stream.c` (`sstp_verify_cert`)

- Проверка DNS SAN (и fallback CN).
- Wildcard по правилам TLS.
- Использовать host из URL/SNI, не сырой IP-literal mismatch без явной политики.
- По возможности опираться на OpenSSL helpers (`X509_check_host` в 1.0.2+/1.1.x).

**Acceptance:** cert with SAN=`vpn.example.com` проходит на host `vpn.example.com`; CN-only legacy cert — documented behavior; wrong SAN fails.

### Phase 3 — Custom CA support
**Files:** `sstp-ios.c`, `PacketTunnelProvider.m`, `VPNManager.m`, Keychain/App Group storage

- UI/settings: optional CA file/PEM (или advanced field).
- Передача CA в tunnel через providerConfiguration / shared storage.
- `SSL_CTX_load_verify_locations` / `SSL_CTX_use_certificate` equivalents for PEM in memory (`SSL_CTX_get_cert_store` + `X509_STORE_add_cert`).
- Mode `custom_ca`.

**Acceptance:** lab server with private CA connects only when that CA is configured; without CA → `tls_cert`.

### Phase 4 — Pinning and/or trust UI for self-signed
**Files:** app UI + tunnel + C verify callback

Вариант A — **Pin (предпочтительнее для automation):**
- пользователь вставляет SHA-256 fingerprint leaf/SPKI;
- verify callback сравнивает pin;
- mismatch → `tls_cert`.

Вариант B — **Trust on first use / explicit trust UI:**
- при unknown/self-signed показать в app fingerprint (нужен app↔extension IPC: start fail details → UI → user confirms → retry with pinned trust);
- сохранить trusted fingerprint в Keychain;
- последующие connect используют pin.

Минимум для v1: **A (pin)** или «import CA». TOFU UI — если хватает ресурса.

**Acceptance:** self-signed сервер работает только после явного pin/CA; без этого — отказ.

### Phase 5 — Wire errors into production-quality channel
**Files:** align with [vpn-production-quality.md](vpn-production-quality.md)

- C fail code `tls_cert` + stage `tcp_tls`.
- Extension last error + UI copy: «Сертификат сервера не доверен / не совпадает с именем».
- Fatal → no auto-reconnect.

**Acceptance:** UI quantifies TLS failure distinctly from DNS/auth.

### Phase 6 — Tests & docs
- Host tests: hostname match helpers (SAN/CN fixtures) where possible without full NE.
- Manual matrix against public CA, expired cert, wrong host, custom CA, pinned self-signed.
- Update `docs/sstp-engine.md` (убрать «VERIFY_NONE / CERTWARN continue» как актуальное поведение после фикса).
- Update `docs/agent-playbook.md` с trust modes.

---

## Suggested file touch list

| Area | Files |
|------|-------|
| SSL init / session | `sstp/sstp-ios.c`, `sstp/sstp-ios.h` |
| Cert verify helpers | `sstp/sstp-stream.c`, `sstp/sstp-stream.h` |
| Options precedent | `sstp/sstp-option.h` (`ca_cert`/`ca_path`), `sstp/sstp-client.c` (reference behavior) |
| Tunnel config | `tunnel/PacketTunnelProvider.m` |
| App settings / trust UI | `com.vn.sstp/ViewController.m`, `VPNManager.m`, possibly new settings helper |
| Storage | Keychain / App Group for CA PEM or pin |
| Docs | `docs/sstp-engine.md`, `docs/agent-playbook.md`, this backlog |

## Manual test matrix

| Scenario | Expected |
|----------|----------|
| Valid public CA + matching host | Connected |
| Valid public CA + wrong host / SAN | Fail `tls_cert` |
| Expired cert | Fail `tls_cert` |
| Self-signed, no pin/CA | Fail `tls_cert` |
| Self-signed + correct custom CA | Connected |
| Self-signed + correct pin | Connected |
| Self-signed + wrong pin | Fail `tls_cert` |
| Debug insecure mode in Release | Must be unavailable / compile-gated |
| MITM proxy with different cert | Fail before PPP |

## Rollout order

1. Phase 0–1 — strict verify by default (largest security win).
2. Phase 2 — SAN/hostname correctness (avoid false fails on real certs).
3. Phase 3–4 — custom CA / pin so lab & enterprise self-signed не блокируются.
4. Phase 5 — UI/error integration with production-quality work.
5. Phase 6 — tests/docs.

**Dependency note:** Phase 1 можно мержить до полного production-quality UI, но желательно сразу давать хоть сырой error string/`tls_cert`, иначе пользователи увидят только «Отключено».

## Open questions

1. Откуда OpenSSL 1.1.x в Network Extension берёт system roots на iOS 15+? Нужен ли bundled `cacert.pem`?
2. Default для IP-literal server (`https://1.2.3.4/`) — требовать pin/CA всегда?
3. Хранить custom CA/pin per-server или глобально?
4. Нужен ли UI в v1 или достаточно advanced config / defaults + pin field?
5. Сохраняем ли `SSTP_OPT_CERTWARN` только под `INSECURE_DEBUG`?

## Relationship to other backlog

| Doc | Role |
|-----|------|
| [tls-certificate-verification.md](tls-certificate-verification.md) (this) | Включить и настроить TLS trust |
| [vpn-production-quality.md](vpn-production-quality.md) | Показать `tls_cert`, stages, no reconnect on fatal |
