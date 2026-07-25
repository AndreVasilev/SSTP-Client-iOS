/*!
 * @file sstp-mschapv2.c
 * @brief MSCHAPv2 / MPPE key helpers (RFC 2759 / 3079).
 */

#include "sstp-mschapv2.h"

#include <string.h>

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/sha.h>

static void unicode_password(const char *pass, uint8_t *out, size_t *out_len)
{
    size_t i;
    size_t n = strlen(pass);
    if (n > 256) n = 256;
    for (i = 0; i < n; i++) {
        out[i * 2] = (uint8_t)pass[i];
        out[i * 2 + 1] = 0;
    }
    *out_len = n * 2;
}

void sstp_mschapv2_nt_password_hash(const char *password, uint8_t hash[16])
{
    uint8_t unicode[512];
    size_t len = 0;
    unicode_password(password, unicode, &len);
    MD4(unicode, (unsigned int)len, hash);
}

static void setup_des_key(const uint8_t key7[7], DES_cblock *key8)
{
    (*key8)[0] = key7[0];
    (*key8)[1] = (uint8_t)(((key7[0] << 7) | (key7[1] >> 1)) & 0xff);
    (*key8)[2] = (uint8_t)(((key7[1] << 6) | (key7[2] >> 2)) & 0xff);
    (*key8)[3] = (uint8_t)(((key7[2] << 5) | (key7[3] >> 3)) & 0xff);
    (*key8)[4] = (uint8_t)(((key7[3] << 4) | (key7[4] >> 4)) & 0xff);
    (*key8)[5] = (uint8_t)(((key7[4] << 3) | (key7[5] >> 5)) & 0xff);
    (*key8)[6] = (uint8_t)(((key7[5] << 2) | (key7[6] >> 6)) & 0xff);
    (*key8)[7] = (uint8_t)((key7[6] << 1) & 0xff);
    DES_set_odd_parity(key8);
}

static void challenge_response(const uint8_t challenge[8],
                               const uint8_t password_hash[16],
                               uint8_t response[24])
{
    uint8_t zhash[21];
    DES_cblock key;
    DES_key_schedule ks;
    memset(zhash, 0, sizeof(zhash));
    memcpy(zhash, password_hash, 16);

    setup_des_key(zhash, &key);
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt((const_DES_cblock *)challenge, (DES_cblock *)response, &ks, DES_ENCRYPT);

    setup_des_key(zhash + 7, &key);
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt((const_DES_cblock *)challenge, (DES_cblock *)(response + 8), &ks, DES_ENCRYPT);

    setup_des_key(zhash + 14, &key);
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt((const_DES_cblock *)challenge, (DES_cblock *)(response + 16), &ks, DES_ENCRYPT);
}

void sstp_mschapv2_challenge_hash(const uint8_t peer_challenge[16],
                                  const uint8_t auth_challenge[16],
                                  const char *username,
                                  uint8_t challenge[8])
{
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    const char *user = strrchr(username, '\\');
    user = user ? user + 1 : username;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, peer_challenge, 16);
    SHA1_Update(&ctx, auth_challenge, 16);
    SHA1_Update(&ctx, user, strlen(user));
    SHA1_Final(digest, &ctx);
    memcpy(challenge, digest, 8);
}

void sstp_mschapv2_generate_nt_response(const uint8_t auth_challenge[16],
                                        const uint8_t peer_challenge[16],
                                        const char *username,
                                        const char *password,
                                        uint8_t nt_response[24])
{
    uint8_t challenge[8];
    uint8_t phash[16];
    sstp_mschapv2_challenge_hash(peer_challenge, auth_challenge, username, challenge);
    sstp_mschapv2_nt_password_hash(password, phash);
    challenge_response(challenge, phash, nt_response);
}

void sstp_mppe_get_new_key_from_sha(const uint8_t master[16],
                                    const uint8_t session[16],
                                    uint8_t out[16])
{
    static const uint8_t shspad1[40];
    uint8_t shspad2[40];
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    memset(shspad2, 0xf2, sizeof(shspad2));

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, master, 16);
    SHA1_Update(&ctx, shspad1, sizeof(shspad1));
    SHA1_Update(&ctx, session, 16);
    SHA1_Update(&ctx, shspad2, sizeof(shspad2));
    SHA1_Final(digest, &ctx);
    memcpy(out, digest, 16);
}
