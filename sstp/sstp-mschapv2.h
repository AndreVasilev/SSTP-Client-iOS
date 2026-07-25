/*!
 * @file sstp-mschapv2.h
 * @brief MSCHAPv2 helpers (RFC 2759) shared by iOS PPP and unit tests.
 */
#ifndef __SSTP_MSCHAPV2_H__
#define __SSTP_MSCHAPV2_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sstp_mschapv2_nt_password_hash(const char *password, uint8_t hash[16]);

void sstp_mschapv2_challenge_hash(const uint8_t peer_challenge[16],
                                  const uint8_t auth_challenge[16],
                                  const char *username,
                                  uint8_t challenge[8]);

void sstp_mschapv2_generate_nt_response(const uint8_t auth_challenge[16],
                                        const uint8_t peer_challenge[16],
                                        const char *username,
                                        const char *password,
                                        uint8_t nt_response[24]);

/*! MPPE GetNewKeyFromSHA (RFC 3079) — first 16 bytes of SHA1. */
void sstp_mppe_get_new_key_from_sha(const uint8_t master[16],
                                    const uint8_t session[16],
                                    uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif /* __SSTP_MSCHAPV2_H__ */
