#include "harness.h"
#include "sstp-ios-error.h"

int main(void)
{
    TEST_ASSERT(sstp_ios_error_code_valid(SSTP_IOS_ERR_DNS_RESOLVE), "dns_resolve valid");
    TEST_ASSERT(sstp_ios_error_code_valid(SSTP_IOS_ERR_TLS_CERT), "tls_cert valid");
    TEST_ASSERT(sstp_ios_error_code_valid(SSTP_IOS_ERR_AUTH_REJECTED), "auth_rejected valid");
    TEST_ASSERT(!sstp_ios_error_code_valid("nope"), "unknown code rejected");
    TEST_ASSERT(!sstp_ios_error_code_valid(NULL), "null code rejected");

    TEST_ASSERT(sstp_ios_stage_valid(SSTP_IOS_STAGE_TCP_TLS), "tcp_tls stage");
    TEST_ASSERT(sstp_ios_stage_valid(SSTP_IOS_STAGE_RECONNECTING), "reconnecting stage");
    TEST_ASSERT(!sstp_ios_stage_valid("weird"), "unknown stage rejected");

    TEST_ASSERT(sstp_ios_error_is_fatal(SSTP_IOS_ERR_AUTH_REJECTED), "auth fatal");
    TEST_ASSERT(sstp_ios_error_is_fatal(SSTP_IOS_ERR_TLS_CERT), "tls_cert fatal");
    TEST_ASSERT(sstp_ios_error_is_fatal(SSTP_IOS_ERR_MISSING_CREDENTIALS), "creds fatal");
    TEST_ASSERT(sstp_ios_error_is_fatal(SSTP_IOS_ERR_CANCELLED), "cancelled fatal");
    TEST_ASSERT(sstp_ios_error_is_fatal(SSTP_IOS_ERR_CRYPTO_BINDING), "binding fatal");
    TEST_ASSERT(!sstp_ios_error_is_fatal(SSTP_IOS_ERR_DNS_RESOLVE), "dns transient");
    TEST_ASSERT(!sstp_ios_error_is_fatal(SSTP_IOS_ERR_TCP_TIMEOUT), "timeout transient");
    TEST_ASSERT(!sstp_ios_error_is_fatal(SSTP_IOS_ERR_NETWORK_LOST), "network_lost transient");

    return test_report("ios_error");
}
