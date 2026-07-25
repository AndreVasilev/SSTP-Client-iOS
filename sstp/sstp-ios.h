/*!
 * @file sstp-ios.h
 * @brief Public API for running SSTP inside an iOS Packet Tunnel.
 */
#ifndef __SSTP_IOS_H__
#define __SSTP_IOS_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sstp_ios_session sstp_ios_session_t;

typedef void (*sstp_ios_ready_fn)(void *ctx,
                                  const char *local_ip,
                                  const char *gateway_ip,
                                  const char *dns1,
                                  const char *dns2);

typedef void (*sstp_ios_packet_fn)(void *ctx, const uint8_t *ip_packet, size_t len);
typedef void (*sstp_ios_fail_fn)(void *ctx, const char *message);

sstp_ios_session_t *sstp_ios_session_create(sstp_ios_ready_fn on_ready,
                                            sstp_ios_packet_fn on_packet,
                                            sstp_ios_fail_fn on_fail,
                                            void *ctx);

int sstp_ios_session_start(sstp_ios_session_t *session,
                           const char *server,
                           const char *username,
                           const char *password);

/** Send a raw IPv4 packet from NEPacketTunnelFlow into the SSTP tunnel. */
int sstp_ios_session_write_ip(sstp_ios_session_t *session,
                              const uint8_t *ip_packet,
                              size_t len);

/** Block on the libevent loop until disconnect/failure. */
void sstp_ios_session_run(sstp_ios_session_t *session);

void sstp_ios_session_stop(sstp_ios_session_t *session);
void sstp_ios_session_free(sstp_ios_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* __SSTP_IOS_H__ */
