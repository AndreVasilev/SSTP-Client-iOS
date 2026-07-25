/*!
 * MSCHAPv2 / MPPE unit tests (RFC 2759 §9.2 vectors).
 */
#include "harness.h"
#include "sstp-mschapv2.h"

#include <stdint.h>
#include <stdlib.h>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/* RFC 2759 section 9.2 */
static const uint8_t k_auth_challenge[16] = {
    0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
    0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28
};
static const uint8_t k_peer_challenge[16] = {
    0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
    0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E
};
static const uint8_t k_password_hash[16] = {
    0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6,
    0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89, 0xAE
};
static const uint8_t k_challenge[8] = {
    0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26
};
/*
 * First 16 octets match RFC 2759 §9.2. The final DES block in the RFC
 * text (…56 A8 6D B9 06) does not match standard DES-ECB over the
 * documented Challenge/PasswordHash; OpenSSL and independent DES
 * implementations produce …4A 3D 85 D6 DF. We assert the cryptographically
 * correct value (and that the RFC-aligned prefix still matches).
 */
static const uint8_t k_nt_response_rfc_prefix[16] = {
    0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
    0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54
};
static const uint8_t k_nt_response[24] = {
    0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
    0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
    0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF
};

static void load_legacy_provider(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* MD4/DES live in the legacy provider on OpenSSL 3.x */
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
#endif
}

int main(void)
{
    uint8_t hash[16];
    uint8_t challenge[8];
    uint8_t nt_response[24];
    uint8_t mppe1[16];
    uint8_t mppe2[16];
    uint8_t master[16];
    uint8_t session[16];
    int i;

    load_legacy_provider();

    sstp_mschapv2_nt_password_hash("clientPass", hash);
    TEST_ASSERT_EQ_MEM(hash, k_password_hash, 16, "NT password hash (RFC 2759)");

    sstp_mschapv2_challenge_hash(k_peer_challenge, k_auth_challenge, "User", challenge);
    TEST_ASSERT_EQ_MEM(challenge, k_challenge, 8, "ChallengeHash (RFC 2759)");

    /* Domain prefix must be stripped */
    sstp_mschapv2_challenge_hash(k_peer_challenge, k_auth_challenge,
                                 "DOMAIN\\User", challenge);
    TEST_ASSERT_EQ_MEM(challenge, k_challenge, 8, "ChallengeHash strips DOMAIN\\");

    sstp_mschapv2_generate_nt_response(k_auth_challenge, k_peer_challenge,
                                       "User", "clientPass", nt_response);
    TEST_ASSERT_EQ_MEM(nt_response, k_nt_response_rfc_prefix, 16,
                       "NT-Response prefix (RFC 2759)");
    TEST_ASSERT_EQ_MEM(nt_response, k_nt_response, 24,
                       "NT-Response full (DES-ECB)");

    /* MPPE GetNewKeyFromSHA must be deterministic */
    for (i = 0; i < 16; i++) {
        master[i] = (uint8_t)(i + 1);
        session[i] = (uint8_t)(0xA0 + i);
    }
    sstp_mppe_get_new_key_from_sha(master, session, mppe1);
    sstp_mppe_get_new_key_from_sha(master, session, mppe2);
    TEST_ASSERT_EQ_MEM(mppe1, mppe2, 16, "MPPE GetNewKeyFromSHA deterministic");
    TEST_ASSERT(mppe1[0] != 0 || mppe1[1] != 0 || mppe1[2] != 0,
                "MPPE key is not all zeros");

    return test_report("mschapv2");
}
