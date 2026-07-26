/*!
 * @file sstp-ios-error.h
 * @brief Stable stage/error codes shared by C engine, tunnel, and app.
 */
#ifndef __SSTP_IOS_ERROR_H__
#define __SSTP_IOS_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Connect / lifecycle stages (string values are part of the public contract). */
#define SSTP_IOS_STAGE_IDLE              "idle"
#define SSTP_IOS_STAGE_RESOLVING         "resolving"
#define SSTP_IOS_STAGE_TCP_TLS           "tcp_tls"
#define SSTP_IOS_STAGE_HTTP_UPGRADE      "http_upgrade"
#define SSTP_IOS_STAGE_SSTP_CONTROL      "sstp_control"
#define SSTP_IOS_STAGE_PPP_LCP           "ppp_lcp"
#define SSTP_IOS_STAGE_PPP_AUTH          "ppp_auth"
#define SSTP_IOS_STAGE_PPP_IPCP          "ppp_ipcp"
#define SSTP_IOS_STAGE_PPP_MPPE          "ppp_mppe"
#define SSTP_IOS_STAGE_APPLYING_SETTINGS "applying_settings"
#define SSTP_IOS_STAGE_CONNECTED         "connected"
#define SSTP_IOS_STAGE_DISCONNECTING     "disconnecting"
#define SSTP_IOS_STAGE_RECONNECTING      "reconnecting"
#define SSTP_IOS_STAGE_ERROR             "error"

/* Machine-readable error codes. */
#define SSTP_IOS_ERR_DNS_RESOLVE         "dns_resolve"
#define SSTP_IOS_ERR_TCP_TIMEOUT         "tcp_timeout"
#define SSTP_IOS_ERR_TLS_HANDSHAKE       "tls_handshake"
#define SSTP_IOS_ERR_TLS_CERT            "tls_cert"
#define SSTP_IOS_ERR_HTTP_UPGRADE        "http_upgrade"
#define SSTP_IOS_ERR_SSTP_CONTROL        "sstp_control"
#define SSTP_IOS_ERR_AUTH_REJECTED       "auth_rejected"
#define SSTP_IOS_ERR_IPCP_FAILED         "ipcp_failed"
#define SSTP_IOS_ERR_CRYPTO_BINDING      "crypto_binding"
#define SSTP_IOS_ERR_MPPE_FAILED         "mppe_failed"
#define SSTP_IOS_ERR_NETWORK_LOST        "network_lost"
#define SSTP_IOS_ERR_MISSING_CREDENTIALS "missing_credentials"
#define SSTP_IOS_ERR_CANCELLED           "cancelled"
#define SSTP_IOS_ERR_INTERNAL            "internal"

/*!
 * @brief Returns non-zero if @a code must not auto-reconnect.
 */
int sstp_ios_error_is_fatal(const char *code);

/*!
 * @brief Returns non-zero if @a code is a known contract value.
 */
int sstp_ios_error_code_valid(const char *code);

/*!
 * @brief Returns non-zero if @a stage is a known contract value.
 */
int sstp_ios_stage_valid(const char *stage);

#ifdef __cplusplus
}
#endif

#endif /* __SSTP_IOS_ERROR_H__ */
