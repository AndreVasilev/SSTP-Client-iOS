/*!
 * @file sstp-ios-error.c
 * @brief Helpers for stable SSTP iOS error/stage contract.
 */

#include <string.h>

#include "sstp-ios-error.h"

int sstp_ios_error_is_fatal(const char *code)
{
    if (!code || !code[0]) {
        return 0;
    }
    if (strcmp(code, SSTP_IOS_ERR_AUTH_REJECTED) == 0 ||
        strcmp(code, SSTP_IOS_ERR_MISSING_CREDENTIALS) == 0 ||
        strcmp(code, SSTP_IOS_ERR_TLS_CERT) == 0 ||
        strcmp(code, SSTP_IOS_ERR_CANCELLED) == 0 ||
        strcmp(code, SSTP_IOS_ERR_CRYPTO_BINDING) == 0) {
        return 1;
    }
    return 0;
}

int sstp_ios_error_code_valid(const char *code)
{
    static const char *const codes[] = {
        SSTP_IOS_ERR_DNS_RESOLVE,
        SSTP_IOS_ERR_TCP_TIMEOUT,
        SSTP_IOS_ERR_TLS_HANDSHAKE,
        SSTP_IOS_ERR_TLS_CERT,
        SSTP_IOS_ERR_HTTP_UPGRADE,
        SSTP_IOS_ERR_SSTP_CONTROL,
        SSTP_IOS_ERR_AUTH_REJECTED,
        SSTP_IOS_ERR_IPCP_FAILED,
        SSTP_IOS_ERR_CRYPTO_BINDING,
        SSTP_IOS_ERR_MPPE_FAILED,
        SSTP_IOS_ERR_NETWORK_LOST,
        SSTP_IOS_ERR_MISSING_CREDENTIALS,
        SSTP_IOS_ERR_CANCELLED,
        SSTP_IOS_ERR_INTERNAL,
        NULL
    };
    int i;
    if (!code) return 0;
    for (i = 0; codes[i]; i++) {
        if (strcmp(code, codes[i]) == 0) return 1;
    }
    return 0;
}

int sstp_ios_stage_valid(const char *stage)
{
    static const char *const stages[] = {
        SSTP_IOS_STAGE_IDLE,
        SSTP_IOS_STAGE_RESOLVING,
        SSTP_IOS_STAGE_TCP_TLS,
        SSTP_IOS_STAGE_HTTP_UPGRADE,
        SSTP_IOS_STAGE_SSTP_CONTROL,
        SSTP_IOS_STAGE_PPP_LCP,
        SSTP_IOS_STAGE_PPP_AUTH,
        SSTP_IOS_STAGE_PPP_IPCP,
        SSTP_IOS_STAGE_PPP_MPPE,
        SSTP_IOS_STAGE_APPLYING_SETTINGS,
        SSTP_IOS_STAGE_CONNECTED,
        SSTP_IOS_STAGE_DISCONNECTING,
        SSTP_IOS_STAGE_RECONNECTING,
        SSTP_IOS_STAGE_ERROR,
        NULL
    };
    int i;
    if (!stage) return 0;
    for (i = 0; stages[i]; i++) {
        if (strcmp(stage, stages[i]) == 0) return 1;
    }
    return 0;
}
