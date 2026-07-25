/*!
 * @file ios-pppd.c
 * @brief In-process PPP for iOS Network Extension (drop-in for sstp-pppd.c).
 */

#include "config.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>

#include "sstp-private.h"

#ifndef PPP_PROTO_LCP
#define PPP_PROTO_LCP  0xc021
#endif
#ifndef PPP_PROTO_IP
#define PPP_PROTO_IP   0x0021
#endif
#ifndef PPP_PROTO_CCP
#define PPP_PROTO_CCP  0x80fd
#endif
#ifndef PPP_PROTO_MPPE
#define PPP_PROTO_MPPE 0x003d
#endif

#define CHAP_MICROSOFT_V2 0x81
#define PPP_MRU           1400

typedef void (*sstp_pppd_ip_fn)(void *arg, const uint8_t *ip, int len);

typedef struct ppp_tx_item {
    struct ppp_tx_item *next;
    sstp_buff_st *buf;
} ppp_tx_item_t;

struct sstp_pppd {
    sstp_stream_st *stream;
    event_base_st *ev_base;
    sstp_chap_st chap;
    sstp_pppd_fn notify;
    void *arg;

    char username[256];
    char password[256];

    uint8_t lcp_id;
    uint8_t chap_id;
    uint8_t ipcp_id;
    uint8_t ccp_id;
    uint32_t magic;

    int lcp_opened;
    int auth_done;
    int ip_configured;
    int ccp_done;
    int mppe_enabled;
    int mppe_keys_set;
    int started;
    int up_notified;
    int tx_busy;

    uint32_t local_ip;
    uint32_t peer_ip;
    uint32_t dns1;
    uint32_t dns2;

    uint8_t mppe_master_send[16];
    uint8_t mppe_master_recv[16];
    uint8_t mppe_session_send[16];
    uint8_t mppe_session_recv[16];
    RC4_KEY rc4_send;
    RC4_KEY rc4_recv;
    uint16_t mppe_send_ccount;
    uint16_t mppe_recv_ccount;

    sstp_pppd_ip_fn ip_handler;
    void *ip_arg;

    ppp_tx_item_t *tx_head;
    ppp_tx_item_t *tx_tail;
    ppp_tx_item_t *tx_inflight;

    unsigned long long sent_bytes;
    unsigned long long recv_bytes;
    unsigned long t_start;
    unsigned long t_end;
};

/* ===== MSCHAPv2 (RFC 2759) ===== */

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

static void nt_password_hash(const char *password, uint8_t hash[16])
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

static void challenge_hash(const uint8_t peer_challenge[16],
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

static void generate_nt_response(const uint8_t auth_challenge[16],
                                 const uint8_t peer_challenge[16],
                                 const char *username,
                                 const char *password,
                                 uint8_t nt_response[24])
{
    uint8_t challenge[8];
    uint8_t phash[16];
    challenge_hash(peer_challenge, auth_challenge, username, challenge);
    nt_password_hash(password, phash);
    challenge_response(challenge, phash, nt_response);
}

/* ===== MPPE 128-bit stateless (RFC 3078/3079) ===== */

static void mppe_get_new_key_from_sha(const uint8_t master[16],
                                      const uint8_t session[16],
                                      uint8_t out[16])
{
    static const uint8_t shspad1[40];
    static const uint8_t shspad2_init = 1;
    uint8_t shspad2[40];
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    (void)shspad2_init;
    memset(shspad2, 0xf2, sizeof(shspad2));

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, master, 16);
    SHA1_Update(&ctx, shspad1, sizeof(shspad1)); /* zero pad */
    SHA1_Update(&ctx, session, 16);
    SHA1_Update(&ctx, shspad2, sizeof(shspad2));
    SHA1_Final(digest, &ctx);
    memcpy(out, digest, 16);
}

static void mppe_rekey(uint8_t master[16], uint8_t session[16],
                       RC4_KEY *rc4, int initial)
{
    uint8_t digest[16];
    mppe_get_new_key_from_sha(master, session, digest);
    if (!initial) {
        /* session = RC4(key=digest)(digest) — matches Linux ppp_mppe */
        RC4_KEY tmp;
        RC4_set_key(&tmp, 16, digest);
        RC4(&tmp, 16, digest, session);
    } else {
        memcpy(session, digest, 16);
    }
    RC4_set_key(rc4, 16, session);
}

static void mppe_init_keys(sstp_pppd_st *ctx)
{
    if (!ctx->mppe_keys_set) {
        log_warn("MPPE keys not ready yet");
        return;
    }
    memcpy(ctx->mppe_session_send, ctx->mppe_master_send, 16);
    memcpy(ctx->mppe_session_recv, ctx->mppe_master_recv, 16);
    mppe_rekey(ctx->mppe_master_send, ctx->mppe_session_send, &ctx->rc4_send, 1);
    mppe_rekey(ctx->mppe_master_recv, ctx->mppe_session_recv, &ctx->rc4_recv, 1);
    /* Kernel starts at 0xfff so the first packet advances to 0 */
    ctx->mppe_send_ccount = 0x0fff;
    ctx->mppe_recv_ccount = 0x0fff;
    ctx->mppe_enabled = 1;
}

/* ===== byte helpers ===== */

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_opt(uint8_t *buf, int *off, uint8_t type, const void *val, uint8_t vlen)
{
    buf[(*off)++] = type;
    buf[(*off)++] = (uint8_t)(2 + vlen);
    if (vlen && val) {
        memcpy(buf + *off, val, vlen);
        *off += vlen;
    }
}

/* ===== send queue (unique buffer per in-flight SSL write) ===== */

static void ppp_tx_free_item(ppp_tx_item_t *item)
{
    if (!item) return;
    if (item->buf) sstp_buff_destroy(item->buf);
    free(item);
}

static void ppp_flush_start(sstp_pppd_st *ctx);

static void ppp_send_complete(sstp_stream_st *stream, sstp_buff_st *buf,
                              void *arg, status_t status)
{
    sstp_pppd_st *ctx = arg;
    (void)stream;
    (void)buf;
    (void)status;

    if (ctx->tx_inflight) {
        ppp_tx_free_item(ctx->tx_inflight);
        ctx->tx_inflight = NULL;
    }
    ctx->tx_busy = 0;
    ppp_flush_start(ctx);
}

static void ppp_flush_start(sstp_pppd_st *ctx)
{
    ppp_tx_item_t *item;
    status_t ret;

    if (!ctx || ctx->tx_busy || !ctx->tx_head || !ctx->stream) {
        return;
    }

    item = ctx->tx_head;
    ctx->tx_head = item->next;
    if (!ctx->tx_head) {
        ctx->tx_tail = NULL;
    }

    ctx->tx_inflight = item;
    ctx->tx_busy = 1;
    ret = sstp_stream_send(ctx->stream, item->buf, ppp_send_complete, ctx, 1);
    if (ret == SSTP_OKAY) {
        ppp_tx_free_item(item);
        ctx->tx_inflight = NULL;
        ctx->tx_busy = 0;
        ppp_flush_start(ctx);
    } else if (ret != SSTP_INPROG) {
        log_err("PPP send failed");
        ppp_tx_free_item(item);
        ctx->tx_inflight = NULL;
        ctx->tx_busy = 0;
    }
}

static status_t ppp_enqueue_raw(sstp_pppd_st *ctx, const uint8_t *frame, int flen)
{
    ppp_tx_item_t *item;
    status_t ret;
    uint8_t *data;

    if (!ctx || !frame || flen <= 0) {
        return SSTP_FAIL;
    }

    item = calloc(1, sizeof(*item));
    if (!item) {
        return SSTP_FAIL;
    }

    ret = sstp_buff_create(&item->buf, flen + 64);
    if (ret != SSTP_OKAY) {
        free(item);
        return SSTP_FAIL;
    }

    ret = sstp_pkt_init(item->buf, SSTP_MSG_DATA);
    if (ret != SSTP_OKAY) {
        ppp_tx_free_item(item);
        return SSTP_FAIL;
    }

    data = (uint8_t *)item->buf->data + item->buf->len;
    memcpy(data, frame, (size_t)flen);
    item->buf->len += flen;
    sstp_pkt_update(item->buf);

    if (!ctx->tx_head) {
        ctx->tx_head = ctx->tx_tail = item;
    } else {
        ctx->tx_tail->next = item;
        ctx->tx_tail = item;
    }

    ctx->sent_bytes += (unsigned long long)flen;
    ppp_flush_start(ctx);
    return SSTP_OKAY;
}

static status_t ppp_send_frame(sstp_pppd_st *ctx, uint16_t proto,
                               const uint8_t *payload, int plen)
{
    uint8_t frame[PPP_MRU + 16];
    int off = 0;

    if (plen < 0 || plen > PPP_MRU) {
        return SSTP_FAIL;
    }

    frame[off++] = 0xFF;
    frame[off++] = 0x03;
    frame[off++] = (uint8_t)((proto >> 8) & 0xff);
    frame[off++] = (uint8_t)(proto & 0xff);
    if (payload && plen > 0) {
        memcpy(frame + off, payload, (size_t)plen);
        off += plen;
    }
    return ppp_enqueue_raw(ctx, frame, off);
}

static status_t ppp_send_ip_plain_or_mppe(sstp_pppd_st *ctx, const uint8_t *ip, int len)
{
    uint8_t plain[PPP_MRU + 8];
    uint8_t enc[PPP_MRU + 16];
    int plain_len;

    if (len <= 0 || len > PPP_MRU - 4) {
        return SSTP_FAIL;
    }

    if (!ctx->mppe_enabled) {
        return ppp_send_frame(ctx, PPP_PROTO_IP, ip, len);
    }

    /* Plaintext = PPP protocol + IP packet (Address/Control are outside MPPE) */
    plain[0] = (uint8_t)((PPP_PROTO_IP >> 8) & 0xff);
    plain[1] = (uint8_t)(PPP_PROTO_IP & 0xff);
    memcpy(plain + 2, ip, (size_t)len);
    plain_len = len + 2;

    /* Stateless: advance coherency, rekey, set A (flushed) + D (encrypted) */
    ctx->mppe_send_ccount = (uint16_t)((ctx->mppe_send_ccount + 1) & 0x0fff);
    mppe_rekey(ctx->mppe_master_send, ctx->mppe_session_send, &ctx->rc4_send, 0);

    enc[0] = (uint8_t)(0x90 | ((ctx->mppe_send_ccount >> 8) & 0x0f));
    enc[1] = (uint8_t)(ctx->mppe_send_ccount & 0xff);
    RC4(&ctx->rc4_send, (size_t)plain_len, plain, enc + 2);

    return ppp_send_frame(ctx, PPP_PROTO_MPPE, enc, plain_len + 2);
}

static void send_ipcp_confreq(sstp_pppd_st *ctx);
static void send_ccp_confreq(sstp_pppd_st *ctx);
static void send_lcp_confreq(sstp_pppd_st *ctx);

static void maybe_notify_up(sstp_pppd_st *ctx)
{
    if (ctx->up_notified) return;
    if (!ctx->ip_configured || ctx->local_ip == 0) return;
    /* Prefer CCP completion so MPPE is armed before traffic starts */
    if (!ctx->ccp_done) return;
    ctx->up_notified = 1;
    log_info("PPP link ready local=%08x peer=%08x mppe=%d",
             ctx->local_ip, ctx->peer_ip, ctx->mppe_enabled);
    if (ctx->notify) {
        ctx->notify(ctx->arg, SSTP_PPP_UP);
    }
}

static void ccp_finished(sstp_pppd_st *ctx)
{
    if (ctx->ccp_done) {
        maybe_notify_up(ctx);
        return;
    }
    ctx->ccp_done = 1;
    if (ctx->auth_done) {
        send_ipcp_confreq(ctx);
    }
    maybe_notify_up(ctx);
}

static void send_lcp_confreq(sstp_pppd_st *ctx)
{
    uint8_t body[64];
    int off = 0;
    uint8_t mru[2];
    uint8_t magic[4];

    put_be16(mru, PPP_MRU);
    put_be32(magic, ctx->magic);

    body[off++] = FSM_CONFREQ;
    body[off++] = ++ctx->lcp_id;
    off += 2;
    put_opt(body, &off, CI_MRU, mru, 2);
    put_opt(body, &off, CI_MAGIC, magic, 4);
    put_be16(body + 2, (uint16_t)off);
    ppp_send_frame(ctx, PPP_PROTO_LCP, body, off);
    log_info("PPP LCP Configure-Request sent");
}

static void send_ipcp_confreq(sstp_pppd_st *ctx)
{
    uint8_t body[64];
    int off = 0;
    uint8_t addr[4];
    uint8_t d1[4];
    uint8_t d2[4];

    put_be32(addr, ctx->local_ip);
    put_be32(d1, ctx->dns1);
    put_be32(d2, ctx->dns2);

    body[off++] = FSM_CONFREQ;
    body[off++] = ++ctx->ipcp_id;
    off += 2;
    put_opt(body, &off, CI_ADDR, addr, 4);
    put_opt(body, &off, CI_MS_DNS1, d1, 4);
    put_opt(body, &off, CI_MS_DNS2, d2, 4);
    put_be16(body + 2, (uint16_t)off);
    ppp_send_frame(ctx, PPP_PROTO_IPCP, body, off);
    log_info("PPP IPCP Configure-Request sent");
}

static void send_ccp_confreq(sstp_pppd_st *ctx)
{
    /* Stateless (H) + 128-bit (S): 01 00 00 40 */
    uint8_t body[32];
    int off = 0;
    uint8_t mppe[4] = {0x01, 0x00, 0x00, 0x40};

    body[off++] = FSM_CONFREQ;
    body[off++] = ++ctx->ccp_id;
    off += 2;
    put_opt(body, &off, CI_MPPC, mppe, 4);
    put_be16(body + 2, (uint16_t)off);
    ppp_send_frame(ctx, PPP_PROTO_CCP, body, off);
}

static void handle_lcp(sstp_pppd_st *ctx, const uint8_t *buf, int len)
{
    uint8_t code, id;
    uint16_t plen;
    if (len < 4) return;
    code = buf[0];
    id = buf[1];
    plen = get_be16(buf + 2);
    if (plen > len) plen = (uint16_t)len;

    switch (code) {
    case FSM_CONFREQ: {
        uint8_t ack[256];
        if (plen > (int)sizeof(ack)) break;
        memcpy(ack, buf, plen);
        ack[0] = FSM_CONFACK;
        ppp_send_frame(ctx, PPP_PROTO_LCP, ack, plen);
        if (!ctx->lcp_opened) {
            send_lcp_confreq(ctx);
        }
        break;
    }
    case FSM_CONFACK:
        ctx->lcp_opened = 1;
        log_info("PPP LCP opened");
        break;
    case FSM_CONFNAK:
    case FSM_CONFREJ:
        send_lcp_confreq(ctx);
        break;
    case FSM_TERMREQ: {
        uint8_t term[4] = {FSM_TERMACK, id, 0, 4};
        ppp_send_frame(ctx, PPP_PROTO_LCP, term, 4);
        if (ctx->notify) ctx->notify(ctx->arg, SSTP_PPP_DOWN);
        break;
    }
    case FSM_ECHOREQ: {
        uint8_t echo[64];
        if (plen > (int)sizeof(echo)) break;
        memcpy(echo, buf, plen);
        echo[0] = FSM_ECHOREP;
        if (plen >= 8) {
            put_be32(echo + 4, ctx->magic);
        }
        ppp_send_frame(ctx, PPP_PROTO_LCP, echo, plen);
        break;
    }
    default:
        break;
    }
}

static void handle_chap(sstp_pppd_st *ctx, const uint8_t *buf, int len)
{
    uint8_t code, id, vsize;
    const uint8_t *auth_challenge;
    uint8_t peer_challenge[16];
    uint8_t nt_response[24];
    uint8_t value[49];
    uint8_t resp[256];
    int off = 0;
    size_t ulen;

    if (len < 5) return;
    code = buf[0];
    id = buf[1];
    vsize = buf[4];

    if (code != CHAP_CHALLENGE) {
        if (code == CHAP_SUCCESS) {
            log_info("MSCHAPv2 authentication succeeded");
            ctx->auth_done = 1;
            /* Negotiate CCP/MPPE before IPCP when possible */
            send_ccp_confreq(ctx);
        } else if (code == CHAP_FAILURE) {
            log_err("MSCHAPv2 authentication failed");
            if (ctx->notify) ctx->notify(ctx->arg, SSTP_PPP_DOWN);
        }
        return;
    }

    if (vsize < 16 || len < 5 + vsize) return;
    auth_challenge = buf + 5;
    ctx->chap_id = id;

    RAND_bytes(peer_challenge, sizeof(peer_challenge));
    generate_nt_response(auth_challenge, peer_challenge, ctx->username,
                         ctx->password, nt_response);

    memcpy(value, peer_challenge, 16);
    memset(value + 16, 0, 8);
    memcpy(value + 24, nt_response, 24);
    value[48] = 0;

    memcpy(ctx->chap.challenge, peer_challenge, 16);
    memcpy(ctx->chap.response, value + 16, 8);
    memcpy(ctx->chap.nt_response, nt_response, 24);
    ctx->chap.flags[0] = 0;

    ulen = strlen(ctx->username);
    if (ulen > 200) ulen = 200;
    resp[off++] = CHAP_RESPONSE;
    resp[off++] = id;
    off += 2;
    resp[off++] = MSCHAP_VALUE_LEN;
    memcpy(resp + off, value, 49);
    off += 49;
    memcpy(resp + off, ctx->username, ulen);
    off += (int)ulen;
    put_be16(resp + 2, (uint16_t)off);

    ppp_send_frame(ctx, PPP_PROTO_CHAP, resp, off);
    log_info("MSCHAPv2 response sent");

    if (ctx->notify) {
        ctx->notify(ctx->arg, SSTP_PPP_AUTH);
    }
}

static void handle_ipcp(sstp_pppd_st *ctx, const uint8_t *buf, int len)
{
    uint8_t code;
    uint16_t plen;
    int pos;

    if (len < 4) return;
    code = buf[0];
    plen = get_be16(buf + 2);
    if (plen > len) plen = (uint16_t)len;

    /* Some servers skip CCP and jump to IPCP after auth */
    if (!ctx->ccp_done && ctx->auth_done) {
        log_warn("Peer started IPCP before CCP completed; continuing without waiting");
        ctx->mppe_enabled = 0;
        ccp_finished(ctx);
    }

    switch (code) {
    case FSM_CONFREQ: {
        uint8_t ack[128];
        pos = 4;
        while (pos + 2 <= plen) {
            uint8_t type = buf[pos];
            uint8_t olen = buf[pos + 1];
            if (olen < 2 || pos + olen > plen) break;
            if (type == CI_ADDR && olen == 6) {
                ctx->peer_ip = get_be32(buf + pos + 2);
            }
            pos += olen;
        }
        if (plen > (int)sizeof(ack)) break;
        memcpy(ack, buf, plen);
        ack[0] = FSM_CONFACK;
        ppp_send_frame(ctx, PPP_PROTO_IPCP, ack, plen);
        break;
    }
    case FSM_CONFACK: {
        pos = 4;
        while (pos + 2 <= plen) {
            uint8_t type = buf[pos];
            uint8_t olen = buf[pos + 1];
            if (olen < 2 || pos + olen > plen) break;
            if (type == CI_ADDR && olen == 6) {
                ctx->local_ip = get_be32(buf + pos + 2);
            } else if (type == CI_MS_DNS1 && olen == 6) {
                ctx->dns1 = get_be32(buf + pos + 2);
            } else if (type == CI_MS_DNS2 && olen == 6) {
                ctx->dns2 = get_be32(buf + pos + 2);
            }
            pos += olen;
        }
        if (ctx->local_ip != 0) {
            ctx->ip_configured = 1;
            maybe_notify_up(ctx);
        }
        break;
    }
    case FSM_CONFNAK: {
        pos = 4;
        while (pos + 2 <= plen) {
            uint8_t type = buf[pos];
            uint8_t olen = buf[pos + 1];
            if (olen < 2 || pos + olen > plen) break;
            if (type == CI_ADDR && olen == 6) {
                ctx->local_ip = get_be32(buf + pos + 2);
            } else if (type == CI_MS_DNS1 && olen == 6) {
                ctx->dns1 = get_be32(buf + pos + 2);
            } else if (type == CI_MS_DNS2 && olen == 6) {
                ctx->dns2 = get_be32(buf + pos + 2);
            }
            pos += olen;
        }
        send_ipcp_confreq(ctx);
        break;
    }
    default:
        break;
    }
}

static void handle_ccp(sstp_pppd_st *ctx, const uint8_t *buf, int len)
{
    uint8_t code;
    uint16_t plen;
    if (len < 4) return;
    code = buf[0];
    plen = get_be16(buf + 2);
    if (plen > len) plen = (uint16_t)len;

    if (code == FSM_CONFREQ) {
        uint8_t ack[64];
        if (plen > (int)sizeof(ack)) return;
        memcpy(ack, buf, plen);
        ack[0] = FSM_CONFACK;
        ppp_send_frame(ctx, PPP_PROTO_CCP, ack, plen);
        mppe_init_keys(ctx);
        log_info("PPP CCP/MPPE enabled (peer request)");
        ccp_finished(ctx);
    } else if (code == FSM_CONFACK) {
        mppe_init_keys(ctx);
        log_info("PPP CCP/MPPE acknowledged");
        ccp_finished(ctx);
    } else if (code == FSM_CONFREJ || code == FSM_CONFNAK) {
        ctx->mppe_enabled = 0;
        log_warn("Server rejected MPPE, continuing without payload encryption");
        ccp_finished(ctx);
    }
}

static void handle_mppe(sstp_pppd_st *ctx, const uint8_t *buf, int len)
{
    uint8_t dec[PPP_MRU + 16];
    uint16_t ccount;
    uint16_t proto;
    const uint8_t *p;
    int plen;

    if (len < 3 || !ctx->mppe_enabled) return;

    ccount = (uint16_t)(((buf[0] & 0x0f) << 8) | buf[1]);

    /* Stateless rekey catch-up (Linux ppp_mppe): rekey until ccounts match */
    while (ctx->mppe_recv_ccount != ccount) {
        mppe_rekey(ctx->mppe_master_recv, ctx->mppe_session_recv, &ctx->rc4_recv, 0);
        ctx->mppe_recv_ccount = (uint16_t)((ctx->mppe_recv_ccount + 1) & 0x0fff);
    }

    RC4(&ctx->rc4_recv, (size_t)(len - 2), buf + 2, dec);
    p = dec;
    plen = len - 2;
    if (plen < 1) return;

    if (p[0] & 0x01) {
        proto = p[0];
        p += 1;
        plen -= 1;
    } else {
        if (plen < 2) return;
        proto = get_be16(p);
        p += 2;
        plen -= 2;
    }

    if (proto == PPP_PROTO_IP && ctx->ip_handler && plen > 0) {
        ctx->ip_handler(ctx->ip_arg, p, plen);
        ctx->recv_bytes += (unsigned long long)plen;
    }
}

static void ppp_dispatch(sstp_pppd_st *ctx, const uint8_t *frame, int len)
{
    const uint8_t *p = frame;
    uint16_t proto;

    if (len < 3) return;
    if (p[0] == 0xFF && p[1] == 0x03) {
        p += 2;
        len -= 2;
    }
    if (len < 2) return;

    if (p[0] & 0x01) {
        proto = p[0];
        p += 1;
        len -= 1;
    } else {
        proto = get_be16(p);
        p += 2;
        len -= 2;
    }

    switch (proto) {
    case PPP_PROTO_LCP:  handle_lcp(ctx, p, len); break;
    case PPP_PROTO_CHAP: handle_chap(ctx, p, len); break;
    case PPP_PROTO_IPCP: handle_ipcp(ctx, p, len); break;
    case PPP_PROTO_CCP:  handle_ccp(ctx, p, len); break;
    case PPP_PROTO_MPPE: handle_mppe(ctx, p, len); break;
    case PPP_PROTO_IP:
        if (ctx->ip_handler) ctx->ip_handler(ctx->ip_arg, p, len);
        ctx->recv_bytes += (unsigned long long)len;
        break;
    default:
        log_debug("Unhandled PPP proto %04x len=%d", proto, len);
        break;
    }
}

/* ===== Public sstp_pppd_* API ===== */

void sstp_pppd_session_details(sstp_pppd_st *ctx, sstp_session_st *sess)
{
    if (!ctx || !sess) return;
    sess->established = ctx->t_end ? (ctx->t_end - ctx->t_start)
                                   : ((unsigned long)time(NULL) - ctx->t_start);
    sess->rx_bytes = ctx->recv_bytes;
    sess->tx_bytes = ctx->sent_bytes;
}

sstp_chap_st *sstp_pppd_getchap(sstp_pppd_st *ctx)
{
    return ctx ? &ctx->chap : NULL;
}

status_t sstp_pppd_create(sstp_pppd_st **ctx, event_base_st *base,
                          sstp_stream_st *stream, sstp_pppd_fn notify, void *arg)
{
    sstp_pppd_st *obj = calloc(1, sizeof(*obj));
    if (!obj) return SSTP_FAIL;

    obj->ev_base = base;
    obj->stream = stream;
    obj->notify = notify;
    obj->arg = arg;
    obj->magic = (uint32_t)arc4random();
    *ctx = obj;
    return SSTP_OKAY;
}

status_t sstp_pppd_start(sstp_pppd_st *ctx, sstp_option_st *opts, const char *sockname)
{
    (void)sockname;
    if (!ctx || !opts) return SSTP_FAIL;

    if (opts->user) {
        strncpy(ctx->username, opts->user, sizeof(ctx->username) - 1);
    }
    if (opts->password) {
        strncpy(ctx->password, opts->password, sizeof(ctx->password) - 1);
    }

    ctx->t_start = (unsigned long)time(NULL);
    ctx->started = 1;

    if (ctx->notify) {
        ctx->notify(ctx->arg, SSTP_PPP_START);
    }

    send_lcp_confreq(ctx);
    return SSTP_OKAY;
}

status_t sstp_pppd_stop(sstp_pppd_st *ctx)
{
    if (!ctx) return SSTP_FAIL;
    ctx->t_end = (unsigned long)time(NULL);
    return SSTP_OKAY;
}

status_t sstp_pppd_send(sstp_pppd_st *ctx, const char *buf, int len)
{
    if (!ctx || !buf || len <= 0) return SSTP_FAIL;
    ppp_dispatch(ctx, (const uint8_t *)buf, len);
    return SSTP_OKAY;
}

void sstp_pppd_free(sstp_pppd_st *ctx)
{
    ppp_tx_item_t *item;
    if (!ctx) return;

    if (ctx->tx_inflight) {
        ppp_tx_free_item(ctx->tx_inflight);
        ctx->tx_inflight = NULL;
    }
    while (ctx->tx_head) {
        item = ctx->tx_head;
        ctx->tx_head = item->next;
        ppp_tx_free_item(item);
    }
    free(ctx);
}

void sstp_pppd_set_ip_handler(sstp_pppd_st *ctx, sstp_pppd_ip_fn fn, void *arg)
{
    if (!ctx) return;
    ctx->ip_handler = fn;
    ctx->ip_arg = arg;
}

void sstp_pppd_set_mppe_keys(sstp_pppd_st *ctx, const uint8_t skey[16], const uint8_t rkey[16])
{
    if (!ctx) return;
    memcpy(ctx->mppe_master_send, skey, 16);
    memcpy(ctx->mppe_master_recv, rkey, 16);
    ctx->mppe_keys_set = 1;
}

status_t sstp_pppd_send_ip(sstp_pppd_st *ctx, const uint8_t *ip, int len)
{
    if (!ctx || !ip || len <= 0) return SSTP_FAIL;
    return ppp_send_ip_plain_or_mppe(ctx, ip, len);
}

void sstp_pppd_get_ipv4(sstp_pppd_st *ctx, char local[16], char peer[16],
                        char dns1[16], char dns2[16])
{
    struct in_addr a;
    if (!ctx) return;
    a.s_addr = htonl(ctx->local_ip);
    inet_ntop(AF_INET, &a, local, 16);
    a.s_addr = htonl(ctx->peer_ip ? ctx->peer_ip : ctx->local_ip);
    inet_ntop(AF_INET, &a, peer, 16);
    a.s_addr = htonl(ctx->dns1 ? ctx->dns1 : 0x08080808u);
    inet_ntop(AF_INET, &a, dns1, 16);
    a.s_addr = htonl(ctx->dns2 ? ctx->dns2 : 0x08080404u);
    inet_ntop(AF_INET, &a, dns2, 16);
}
