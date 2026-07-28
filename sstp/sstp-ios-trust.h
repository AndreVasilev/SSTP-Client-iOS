/*!
 * @file sstp-ios-trust.h
 * @brief Bridge from OpenSSL peer certificates to iOS SecTrust evaluation.
 *
 * Used by SSTP_IOS_TLS_SYSTEM so corporate / MDM roots installed on the device
 * are honored (OpenSSL's bundled cacert.pem does not see the iOS trust store).
 */
#ifndef __SSTP_IOS_TRUST_H__
#define __SSTP_IOS_TRUST_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Evaluate a TLS server certificate chain against the iOS system trust store.
 *
 * @param ders      Array of DER-encoded certificates; ders[0] must be the leaf.
 * @param lens      Parallel array of DER lengths.
 * @param count     Number of certificates (at least 1).
 * @param hostname  Expected DNS name or IP literal (used by SSL policy).
 * @param errmsg    Optional buffer for a human-readable failure reason.
 * @param errmsg_len Size of errmsg.
 * @return 0 on success (trusted), -1 on failure.
 */
int sstp_ios_sec_trust_evaluate(const unsigned char *const *ders,
                                const size_t *lens,
                                size_t count,
                                const char *hostname,
                                char *errmsg,
                                size_t errmsg_len);

#ifdef __cplusplus
}
#endif

#endif /* __SSTP_IOS_TRUST_H__ */
