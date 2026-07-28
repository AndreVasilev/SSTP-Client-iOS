/*!
 * @file sstp-ios.h
 * @brief Public API for running SSTP inside an iOS Packet Tunnel.
 */
#ifndef __SSTP_IOS_H__
#define __SSTP_IOS_H__

#include <stddef.h>
#include <stdint.h>

#include "sstp-ios-error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sstp_ios_session sstp_ios_session_t;

typedef enum {
    SSTP_IOS_TLS_SYSTEM = 0,
    SSTP_IOS_TLS_CUSTOM_CA = 1,
    SSTP_IOS_TLS_PINNED = 2,
    SSTP_IOS_TLS_INSECURE_DEBUG = 3  /* Debug builds only */
} sstp_ios_tls_mode_t;

typedef struct sstp_ios_start_params {
    const char *server;          /* legacy combined endpoint or host */
    const char *server_host;     /* optional explicit DNS/IP host for SNI/verify */
    const char *server_port;     /* optional explicit TCP port (default 443) */
    const char *username;
    const char *password;
    sstp_ios_tls_mode_t tls_mode;
    const char *ca_pem;          /* PEM bytes for custom_ca; may be NULL */
    size_t ca_pem_len;
    const char *pin_sha256_hex;  /* 64 hex chars (leaf SHA-256); may be NULL */
} sstp_ios_start_params_t;

typedef void (*sstp_ios_ready_fn)(void *ctx,
                                  const char *local_ip,
                                  const char *gateway_ip,
                                  const char *dns1,
                                  const char *dns2);

typedef void (*sstp_ios_packet_fn)(void *ctx, const uint8_t *ip_packet, size_t len);
typedef void (*sstp_ios_stage_fn)(void *ctx, const char *stage);
typedef void (*sstp_ios_fail_fn)(void *ctx,
                                 const char *code,
                                 const char *stage,
                                 const char *message);

sstp_ios_session_t *sstp_ios_session_create(sstp_ios_ready_fn on_ready,
                                            sstp_ios_packet_fn on_packet,
                                            sstp_ios_stage_fn on_stage,
                                            sstp_ios_fail_fn on_fail,
                                            void *ctx);

/** Convenience start with system TLS trust (default production profile). */
int sstp_ios_session_start(sstp_ios_session_t *session,
                           const char *server,
                           const char *username,
                           const char *password);

/** Start with explicit TLS trust parameters. */
int sstp_ios_session_start_ex(sstp_ios_session_t *session,
                              const sstp_ios_start_params_t *params);

/** Send a raw IPv4 packet from NEPacketTunnelFlow into the SSTP tunnel. */
int sstp_ios_session_write_ip(sstp_ios_session_t *session,
                              const uint8_t *ip_packet,
                              size_t len);

/** Block on the libevent loop until disconnect/failure. */
void sstp_ios_session_run(sstp_ios_session_t *session);

void sstp_ios_session_stop(sstp_ios_session_t *session);
void sstp_ios_session_free(sstp_ios_session_t *session);

const char *sstp_ios_session_stage(const sstp_ios_session_t *session);
const char *sstp_ios_session_last_error_code(const sstp_ios_session_t *session);
const char *sstp_ios_session_last_error_message(const sstp_ios_session_t *session);
int sstp_ios_session_is_ready(const sstp_ios_session_t *session);

/**
 * Legacy single-string fail path (used by sstp_die). Maps to code=internal.
 * Prefer sstp_ios_fail_ex from new code.
 */
void sstp_ios_fail(const char *message);

/** Structured fail used by the iOS session path. */
void sstp_ios_fail_ex(const char *code, const char *stage, const char *message);

/** Publish a stage transition (no-op if session inactive). */
void sstp_ios_set_stage(const char *stage);

#ifdef __cplusplus
}
#endif

#endif /* __SSTP_IOS_H__ */
