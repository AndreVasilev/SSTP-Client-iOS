#include "harness.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

static X509 *make_cert_with_san(const char *san_value)
{
    X509 *cert = X509_new();
    EVP_PKEY *pkey = NULL;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    X509_NAME *name;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_IA5STRING *ia5 = NULL;

    if (!cert || !rsa || !e) return NULL;
    if (!BN_set_word(e, RSA_F4)) return NULL;
    if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) return NULL;
    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_RSA(pkey, rsa)) return NULL;
    rsa = NULL;

    if (!X509_set_version(cert, 2)) return NULL;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24);
    if (!X509_set_pubkey(cert, pkey)) return NULL;

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"legacy.example.com", -1, -1, 0);
    if (!X509_set_issuer_name(cert, name)) return NULL;

    if (san_value && san_value[0]) {
        gens = sk_GENERAL_NAME_new_null();
        gen = GENERAL_NAME_new();
        ia5 = ASN1_IA5STRING_new();
        if (!gens || !gen || !ia5) return NULL;
        ASN1_STRING_set(ia5, san_value, (int)strlen(san_value));
        GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
        ia5 = NULL;
        sk_GENERAL_NAME_push(gens, gen);
        gen = NULL;
        if (!X509_add1_ext_i2d(cert, NID_subject_alt_name, gens, 0, 0)) return NULL;
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
        gens = NULL;
    }

    if (!X509_sign(cert, pkey, EVP_sha256())) return NULL;
    EVP_PKEY_free(pkey);
    BN_free(e);
    return cert;
}

int main(void)
{
    X509 *cert;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_crypto(0, NULL);
#endif

    cert = make_cert_with_san("vpn.example.com");
    TEST_ASSERT(cert != NULL, "create SAN cert");
    TEST_ASSERT(X509_check_host(cert, "vpn.example.com", 0, 0, NULL) == 1,
                "SAN exact match");
    TEST_ASSERT(X509_check_host(cert, "other.example.com", 0, 0, NULL) != 1,
                "SAN mismatch fails");
    X509_free(cert);

    cert = make_cert_with_san("*.example.com");
    TEST_ASSERT(cert != NULL, "create wildcard SAN cert");
    TEST_ASSERT(X509_check_host(cert, "vpn.example.com", 0, 0, NULL) == 1,
                "wildcard SAN match");
    TEST_ASSERT(X509_check_host(cert, "example.com", 0, 0, NULL) != 1,
                "wildcard does not match apex");
    X509_free(cert);

    cert = make_cert_with_san(NULL);
    TEST_ASSERT(cert != NULL, "create CN-only cert");
    TEST_ASSERT(X509_check_host(cert, "legacy.example.com", 0, 0, NULL) == 1,
                "CN fallback match");
    TEST_ASSERT(X509_check_host(cert, "vpn.example.com", 0, 0, NULL) != 1,
                "CN mismatch fails");
    X509_free(cert);

    return test_report("cert_host");
}
