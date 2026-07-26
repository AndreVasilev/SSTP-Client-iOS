# Архитектура

## Слои

```text
┌─────────────────────────────────────────────┐
│  App target (com.vn.sstp)                   │
│  ViewController → VPNManager → Keychain     │
│  NETunnelProviderManager / startVPNTunnel   │
└─────────────────────┬───────────────────────┘
                      │ start options + profile
                      ▼
┌─────────────────────────────────────────────┐
│  Extension target (tunnel.appex)            │
│  PacketTunnelProvider                       │
│  NEPacketTunnelFlow ←→ IP packets           │
└─────────────────────┬───────────────────────┘
                      │ sstp_ios_* API
                      ▼
┌─────────────────────────────────────────────┐
│  SSTP engine (C, shared sources)            │
│  sstp-ios.c  → stream/http/state            │
│  ios-pppd.c  → LCP/CHAP/IPCP/CCP/MPPE       │
│  OpenSSL + libevent                         │
└─────────────────────────────────────────────┘
```

Оба Xcode-таргета компилируют одни и те же SSTP C-исходники. Runtime-точка входа туннеля — только extension.

## Connect sequence

```text
User taps Connect
  → ViewController validates fields
  → VPNManager.saveConfiguration(...)
       - NSUserDefaults: server, username
       - Keychain: password + passwordReference
       - NETunnelProviderProtocol (+ providerConfiguration)
  → VPNManager.connectWithCompletion
       - startVPNTunnelWithOptions: {server, username, password}
  → PacketTunnelProvider.startTunnelWithOptions
       - sstp_ios_session_create / start / run (worker thread)
       - TLS connect → HTTP SSTP handshake → CALL_CONNECT
       - ios-pppd: LCP → MSCHAPv2 → IPCP → CCP/MPPE
       - on_ready(local, gateway, dns…)
       - setTunnelNetworkSettings + startPacketLoop
  → status UI updates via VPNManagerStatusDidChangeNotification
```

## Disconnect sequence

```text
User taps Disconnect  (or system stops tunnel)
  → VPNManager.disconnect  /  stopTunnelWithReason
  → PacketTunnelProvider:
       packetLoopRunning = NO
       sstp_ios_session_stop
       wait worker thread
       sstp_ios_session_free
```

## Поток пакетов

**Device → VPN server**

```text
apps → NEPacketTunnelFlow.readPackets
     → sstp_ios_session_write_ip
     → socketpair inject into libevent thread
     → ios-pppd (optional MPPE) → SSTP data packet → TLS stream
```

**VPN server → device**

```text
TLS stream → SSTP data → ios-pppd decrypt/dispatch IP
          → on_packet callback
          → packetFlow.writePackets (AF_INET)
```

## Ключевые runtime-константы

| Параметр | Значение | Где |
|----------|----------|-----|
| SSTP URL | `https://%s/` | `sstp-ios.c` |
| Порт по умолчанию | `443` | `sstp-ios.c` |
| Connect timeout | `60` s | `sstp-ios.c` |
| Tunnel MTU | `1400` | `PacketTunnelProvider.m` |
| PPP MRU | `1400` | `ios-pppd.c` |
| Max inject IP len | `2000` | `sstp-ios.c` |
| DNS fallback | `8.8.8.8`, `8.8.4.4` | `PacketTunnelProvider.m` |
| Local/gateway fallback | `10.0.0.2` / `10.0.0.1` | `PacketTunnelProvider.m` |

## Состояние VPN в app

`VPNManager` слушает `NEVPNStatusDidChangeNotification` и репостит как:

`VPNManagerStatusDidChangeNotification`

UI не держит отдельную state machine — опирается на `NEVPNStatus` через `VPNManager`.

## Связанные документы

- App layer → [app-layer.md](app-layer.md)
- Tunnel → [tunnel-layer.md](tunnel-layer.md)
- SSTP engine → [sstp-engine.md](sstp-engine.md)
