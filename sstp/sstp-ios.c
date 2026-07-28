/*!
 * @file sstp-ios.c
 * @brief SSTP session runner for iOS Packet Tunnel Provider.
 */

#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

/* private.h must come first: it defines status_t / stream / option types */
#include "sstp-private.h"
#include "sstp-client.h"
#include "sstp-ios.h"
#include "sstp-ios-trust.h"

void sstp_pppd_set_ip_handler(sstp_pppd_st *ctx, void (*fn)(void *, const uint8_t *, int), void *arg);
void sstp_pppd_set_mppe_keys(sstp_pppd_st *ctx, const uint8_t skey[16], const uint8_t rkey[16]);
status_t sstp_pppd_send_ip(sstp_pppd_st *ctx, const uint8_t *ip, int len);
void sstp_pppd_get_ipv4(sstp_pppd_st *ctx, char local[16], char peer[16], char dns1[16], char dns2[16]);

struct sstp_ios_session {
    sstp_client_st client;
    sstp_ios_ready_fn on_ready;
    sstp_ios_packet_fn on_packet;
    sstp_ios_stage_fn on_stage;
    sstp_ios_fail_fn on_fail;
    void *ctx;
    int failed;
    int ready;
    char stage[64];
    char fail_code[64];
    char fail_msg[256];
    jmp_buf escape;
    int escape_set;

    sstp_ios_tls_mode_t tls_mode;
    char *ca_pem;
    size_t ca_pem_len;
    char pin_sha256_hex[65];

    /* Cross-thread IP injection into the libevent loop */
    int inject_fds[2];
    event_st *inject_ev;
    int stop_fds[2];
    event_st *stop_ev;
};

static sstp_ios_session_t *g_current;

static const char *ios_tls_mode_name(sstp_ios_tls_mode_t mode)
{
    switch (mode) {
    case SSTP_IOS_TLS_SYSTEM: return "system";
    case SSTP_IOS_TLS_CUSTOM_CA: return "custom_ca";
    case SSTP_IOS_TLS_PINNED: return "pinned";
    case SSTP_IOS_TLS_INSECURE_DEBUG: return "insecure_debug";
    default: return "unknown";
    }
}

static void ios_log_x509_line(const char *label, X509 *cert, int depth)
{
    char subj[256];
    char issr[256];
    if (!cert) return;
    subj[0] = issr[0] = '\0';
    X509_NAME_oneline(X509_get_subject_name(cert), subj, (int)sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), issr, (int)sizeof(issr));
    log_debug("TLS verify depth=%d %s subject=%s issuer=%s",
              depth, label ? label : "cert", subj, issr);
}

void sstp_ios_set_stage(const char *stage)
{
    if (!g_current || !stage) return;
    snprintf(g_current->stage, sizeof(g_current->stage), "%s", stage);
    if (g_current->on_stage) {
        g_current->on_stage(g_current->ctx, g_current->stage);
    }
}

void sstp_ios_fail_ex(const char *code, const char *stage, const char *message)
{
    if (!g_current) return;
    g_current->failed = 1;
    snprintf(g_current->fail_code, sizeof(g_current->fail_code), "%s",
             code && code[0] ? code : SSTP_IOS_ERR_INTERNAL);
    if (stage && stage[0]) {
        snprintf(g_current->stage, sizeof(g_current->stage), "%s", stage);
    } else if (!g_current->stage[0]) {
        snprintf(g_current->stage, sizeof(g_current->stage), "%s", SSTP_IOS_STAGE_ERROR);
    }
    snprintf(g_current->fail_msg, sizeof(g_current->fail_msg), "%s",
             message ? message : "SSTP failure");
    log_err("SSTP fail code=%s stage=%s msg=%s",
            g_current->fail_code, g_current->stage, g_current->fail_msg);
    if (g_current->on_fail) {
        g_current->on_fail(g_current->ctx,
                           g_current->fail_code,
                           g_current->stage,
                           g_current->fail_msg);
    }
    if (g_current->client.ev_base) {
        event_base_loopbreak(g_current->client.ev_base);
    }
    if (g_current->escape_set) {
        longjmp(g_current->escape, 1);
    }
}

void sstp_ios_fail(const char *message)
{
    sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL,
                     g_current ? g_current->stage : SSTP_IOS_STAGE_ERROR,
                     message);
}

static void ios_ip_handler(void *arg, const uint8_t *ip, int len)
{
    sstp_ios_session_t *session = arg;
    if (session && session->on_packet && ip && len > 0) {
        session->on_packet(session->ctx, ip, (size_t)len);
    }
}

static void ios_inject_cb(evutil_socket_t fd, short what, void *arg)
{
    sstp_ios_session_t *session = arg;
    uint8_t hdr[4];
    uint8_t packet[2048];
    uint32_t len = 0;
    ssize_t n;
    (void)what;

    for (;;) {
        n = read(fd, hdr, sizeof(hdr));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        if (n == 0) return;
        if (n != (ssize_t)sizeof(hdr)) return;

        len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
              ((uint32_t)hdr[2] << 8) | hdr[3];
        if (len == 0 || len > sizeof(packet)) {
            continue;
        }
        n = read(fd, packet, len);
        if (n != (ssize_t)len) return;

        if (session->client.pppd) {
            sstp_pppd_send_ip(session->client.pppd, packet, (int)len);
        }
    }
}

static void ios_stop_cb(evutil_socket_t fd, short what, void *arg)
{
    sstp_ios_session_t *session = arg;
    char buf[16];
    (void)what;
    while (read(fd, buf, sizeof(buf)) > 0) {
    }
    if (session->client.ev_base) {
        event_base_loopbreak(session->client.ev_base);
    }
}

static int ios_make_nonblock_pipe(int fds[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
#ifdef EVUTIL_SOCK_NONBLOCK
    evutil_make_socket_nonblocking(fds[0]);
    evutil_make_socket_nonblocking(fds[1]);
#else
    {
        int fl0 = fcntl(fds[0], F_GETFL, 0);
        int fl1 = fcntl(fds[1], F_GETFL, 0);
        if (fl0 >= 0) fcntl(fds[0], F_SETFL, fl0 | O_NONBLOCK);
        if (fl1 >= 0) fcntl(fds[1], F_SETFL, fl1 | O_NONBLOCK);
    }
#endif
    return 0;
}

static int ios_hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int ios_parse_sha256_hex(const char *hex, unsigned char out[32])
{
    size_t i;
    if (!hex || strlen(hex) != 64) return -1;
    for (i = 0; i < 32; i++) {
        int hi = ios_hex_nibble(hex[i * 2]);
        int lo = ios_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static int ios_load_custom_ca(SSL_CTX *ssl_ctx, const char *pem, size_t pem_len)
{
    BIO *bio;
    X509_STORE *store;
    int loaded = 0;

    if (!ssl_ctx || !pem || pem_len == 0) return -1;
    bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) return -1;
    store = SSL_CTX_get_cert_store(ssl_ctx);
    if (!store) {
        BIO_free(bio);
        return -1;
    }

    for (;;) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert) break;
        if (X509_STORE_add_cert(store, cert) == 1) {
            loaded++;
        }
        X509_free(cert);
    }
    ERR_clear_error();
    BIO_free(bio);
    return loaded > 0 ? 0 : -1;
}

static int ios_load_bundled_or_default_ca(SSL_CTX *ssl_ctx)
{
    const char *loaded_from = NULL;

    /* Prefer OpenSSL default paths (useful on host tests); then common bundle names. */
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) == 1) {
        loaded_from = "OpenSSL default verify paths";
        log_debug("CA store loaded from %s", loaded_from);
        return 0;
    }
    ERR_clear_error();
#ifdef SSTP_IOS_CA_BUNDLE_PATH
    if (SSL_CTX_load_verify_locations(ssl_ctx, SSTP_IOS_CA_BUNDLE_PATH, NULL) == 1) {
        loaded_from = SSTP_IOS_CA_BUNDLE_PATH;
        log_debug("CA store loaded from compile-time bundle %s", loaded_from);
        return 0;
    }
    ERR_clear_error();
#endif
    /* Bundle shipped next to the extension binary as cacert.pem */
    {
        char path[1024];
        const char *home = getenv("SSTP_CA_BUNDLE");
        if (home && home[0] && SSL_CTX_load_verify_locations(ssl_ctx, home, NULL) == 1) {
            loaded_from = home;
            log_debug("CA store loaded from SSTP_CA_BUNDLE=%s", loaded_from);
            return 0;
        }
        /* Relative fallbacks used by unit/host tooling */
        if (SSL_CTX_load_verify_locations(ssl_ctx, "cacert.pem", NULL) == 1) {
            loaded_from = "cacert.pem";
            log_debug("CA store loaded from %s", loaded_from);
            return 0;
        }
        snprintf(path, sizeof(path), "%s", "/etc/ssl/cert.pem");
        if (SSL_CTX_load_verify_locations(ssl_ctx, path, NULL) == 1) {
            loaded_from = path;
            log_debug("CA store loaded from %s", loaded_from);
            return 0;
        }
        snprintf(path, sizeof(path), "%s", "/etc/ssl/certs/ca-certificates.crt");
        if (SSL_CTX_load_verify_locations(ssl_ctx, path, NULL) == 1) {
            loaded_from = path;
            log_debug("CA store loaded from %s", loaded_from);
            return 0;
        }
    }
    ERR_clear_error();
    log_warn("Could not load any OpenSSL CA store (bundled/system paths unavailable)");
    return -1;
}

static int ios_pin_matches(X509 *cert, const char *pin_hex)
{
    unsigned char want[32];
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!cert || !pin_hex[0]) return 0;
    if (ios_parse_sha256_hex(pin_hex, want) != 0) return 0;
    if (X509_digest(cert, EVP_sha256(), dig, &dlen) != 1 || dlen != 32) {
        return 0;
    }
    return CRYPTO_memcmp(dig, want, 32) == 0;
}

static int ios_verify_callback(int preverify_ok, X509_STORE_CTX *xctx)
{
    sstp_ios_session_t *session = g_current;
    X509 *cert;
    int depth;
    int err;
    const char *errstr;

    if (!session) return preverify_ok;
    if (session->tls_mode == SSTP_IOS_TLS_INSECURE_DEBUG) {
        return 1;
    }

    /* System mode: OpenSSL must not reject corporate roots that exist only in
     * the iOS trust store. Defer chain+hostname to SecTrust after handshake. */
    if (session->tls_mode == SSTP_IOS_TLS_SYSTEM) {
        depth = X509_STORE_CTX_get_error_depth(xctx);
        cert = X509_STORE_CTX_get_current_cert(xctx);
        ios_log_x509_line("system-defer", cert, depth);
        return 1;
    }

    depth = X509_STORE_CTX_get_error_depth(xctx);
    cert = X509_STORE_CTX_get_current_cert(xctx);
    err = X509_STORE_CTX_get_error(xctx);
    errstr = X509_verify_cert_error_string(err);
    ios_log_x509_line("verify-callback", cert, depth);
    log_debug("TLS verify callback depth=%d preverify_ok=%d err=%d (%s)",
              depth, preverify_ok, err, errstr ? errstr : "unknown");

    if (session->tls_mode == SSTP_IOS_TLS_PINNED && depth == 0 && cert) {
        if (ios_pin_matches(cert, session->pin_sha256_hex)) {
            log_debug("Pinned leaf certificate hash matched");
            return 1;
        }
        log_info("Pinned leaf certificate hash mismatch");
        return 0;
    }

    if (!preverify_ok) {
        log_info("OpenSSL preverify failed at depth=%d: %s (%d)",
                 depth, errstr ? errstr : "unknown", err);
    }
    return preverify_ok;
}

static int ios_x509_to_der(X509 *cert, unsigned char **out, size_t *out_len)
{
    int len;
    unsigned char *buf = NULL;
    unsigned char *p;

    if (!cert || !out || !out_len) return -1;
    len = i2d_X509(cert, NULL);
    if (len <= 0) return -1;
    buf = malloc((size_t)len);
    if (!buf) return -1;
    p = buf;
    if (i2d_X509(cert, &p) != len) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (size_t)len;
    return 0;
}

/**
 * Evaluate peer chain via iOS SecTrust (SYSTEM TLS mode).
 * Returns 0 on success, -1 on failure (fail_ex already called).
 */
static int ios_evaluate_system_trust(sstp_stream_st *stream, const char *hostname)
{
    SSL *ssl;
    X509 *leaf = NULL;
    STACK_OF(X509) *chain = NULL;
    unsigned char **ders = NULL;
    size_t *lens = NULL;
    size_t count = 0;
    size_t capacity = 0;
    size_t i;
    int rc = -1;
    char errmsg[192];

    log_info("Evaluating server certificate via iOS SecTrust for host=%s",
             hostname ? hostname : "(null)");

    ssl = (SSL *)sstp_stream_get_ssl(stream);
    if (!ssl) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT, SSTP_IOS_STAGE_TCP_TLS,
                         "No SSL session for system trust evaluation");
        return -1;
    }

    leaf = SSL_get_peer_certificate(ssl);
    if (!leaf) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT, SSTP_IOS_STAGE_TCP_TLS,
                         "Server did not present a certificate");
        return -1;
    }
    ios_log_x509_line("sectrust-leaf", leaf, 0);

    chain = SSL_get_peer_cert_chain(ssl);
    capacity = 1 + (size_t)(chain ? sk_X509_num(chain) : 0);
    ders = calloc(capacity, sizeof(*ders));
    lens = calloc(capacity, sizeof(*lens));
    if (!ders || !lens) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL, SSTP_IOS_STAGE_TCP_TLS,
                         "Out of memory building certificate chain");
        goto done;
    }

    if (ios_x509_to_der(leaf, &ders[count], &lens[count]) != 0) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT, SSTP_IOS_STAGE_TCP_TLS,
                         "Could not encode peer certificate");
        goto done;
    }
    log_debug("SecTrust chain[%zu] leaf DER len=%zu", count, lens[count]);
    count++;

    if (chain) {
        int n = sk_X509_num(chain);
        for (i = 0; i < (size_t)n; i++) {
            X509 *cert = sk_X509_value(chain, (int)i);
            if (!cert) continue;
            /* Peer chain often includes the leaf again — skip duplicates. */
            if (X509_cmp(cert, leaf) == 0) continue;
            if (ios_x509_to_der(cert, &ders[count], &lens[count]) != 0) {
                sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT, SSTP_IOS_STAGE_TCP_TLS,
                                 "Could not encode intermediate certificate");
                goto done;
            }
            log_debug("SecTrust chain[%zu] intermediate DER len=%zu", count, lens[count]);
            count++;
        }
    }

    errmsg[0] = '\0';
    if (sstp_ios_sec_trust_evaluate((const unsigned char *const *)ders, lens,
                                    count, hostname, errmsg, sizeof(errmsg)) != 0) {
        log_info("SecTrust rejected certificate for %s: %s",
                 hostname ? hostname : "(null)",
                 errmsg[0] ? errmsg : "unknown reason");
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT, SSTP_IOS_STAGE_TCP_TLS,
                         errmsg[0] ? errmsg
                                   : "iOS system trust rejected server certificate");
        goto done;
    }

    log_info("iOS system trust accepted server certificate for %s (chain_len=%zu)",
             hostname, count);
    rc = 0;

done:
    if (leaf) X509_free(leaf);
    if (ders) {
        for (i = 0; i < count; i++) {
            free(ders[i]);
        }
        free(ders);
    }
    free(lens);
    return rc;
}

static status_t ios_init_ssl(sstp_ios_session_t *session)
{
    sstp_client_st *client = &session->client;
    int verify_mode = SSL_VERIFY_PEER;

    client->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!client->ssl_ctx) {
        return SSTP_FAIL;
    }
    SSL_CTX_set_options(client->ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(client->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif

#if !defined(DEBUG) && !defined(_DEBUG)
    if (session->tls_mode == SSTP_IOS_TLS_INSECURE_DEBUG) {
        log_err("INSECURE_DEBUG TLS mode is unavailable in Release builds");
        return SSTP_FAIL;
    }
#endif

    if (session->tls_mode == SSTP_IOS_TLS_INSECURE_DEBUG) {
        verify_mode = SSL_VERIFY_NONE;
        SSL_CTX_set_verify(client->ssl_ctx, verify_mode, NULL);
        return SSTP_OKAY;
    }

    SSL_CTX_set_verify(client->ssl_ctx, verify_mode, ios_verify_callback);

    if (session->tls_mode == SSTP_IOS_TLS_CUSTOM_CA) {
        log_info("TLS init mode=custom_ca ca_pem_len=%zu", session->ca_pem_len);
        if (ios_load_custom_ca(client->ssl_ctx, session->ca_pem, session->ca_pem_len) != 0) {
            log_err("Failed to load custom CA PEM");
            return SSTP_FAIL;
        }
    } else if (session->tls_mode == SSTP_IOS_TLS_PINNED) {
        log_info("TLS init mode=pinned pin=%s",
                 session->pin_sha256_hex[0] ? "set" : "missing");
        /* Pinning validates leaf hash in callback; still load roots for date/path when possible. */
        (void)ios_load_bundled_or_default_ca(client->ssl_ctx);
        if (!session->pin_sha256_hex[0]) {
            log_err("Pinned TLS mode requires pin_sha256_hex");
            return SSTP_FAIL;
        }
    } else if (session->tls_mode == SSTP_IOS_TLS_SYSTEM) {
        log_info("TLS init mode=system (trust via iOS SecTrust after handshake)");
        /* Trust decision is SecTrust (iOS trust store / MDM roots). Bundled
         * Mozilla CA is optional and unused for accept/reject. */
        (void)ios_load_bundled_or_default_ca(client->ssl_ctx);
        SSL_CTX_set_verify(client->ssl_ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           ios_verify_callback);
    } else {
        log_info("TLS init mode=%s (OpenSSL bundled/system CA store)",
                 ios_tls_mode_name(session->tls_mode));
        if (ios_load_bundled_or_default_ca(client->ssl_ctx) != 0) {
            log_warn("Could not load system/bundled CA store; certificate verify may fail");
        }
    }

    log_debug("TLS verify_mode=0x%x", SSL_CTX_get_verify_mode(client->ssl_ctx));

    return SSTP_OKAY;
}

static void ios_pppd_cb(sstp_client_st *client, sstp_pppd_event_t ev)
{
    sstp_ios_session_t *session = g_current;
    int ret;

    switch (ev) {
    case SSTP_PPP_START:
        sstp_ios_set_stage(SSTP_IOS_STAGE_PPP_LCP);
        sstp_state_resume_recv(client->state);
        break;

    case SSTP_PPP_DOWN:
        log_err("PPP terminated");
        sstp_ios_fail_ex(SSTP_IOS_ERR_NETWORK_LOST,
                         SSTP_IOS_STAGE_PPP_LCP,
                         "PPP connection terminated");
        break;

    case SSTP_PPP_AUTH_FAIL:
        sstp_ios_fail_ex(SSTP_IOS_ERR_AUTH_REJECTED,
                         SSTP_IOS_STAGE_PPP_AUTH,
                         "Authentication rejected by server");
        break;

    case SSTP_PPP_UP: {
        char local[16], peer[16], dns1[16], dns2[16];
        sstp_ios_set_stage(SSTP_IOS_STAGE_PPP_IPCP);
        ret = sstp_state_accept(client->state);
        if (ret == SSTP_FAIL) {
            sstp_ios_fail_ex(SSTP_IOS_ERR_CRYPTO_BINDING,
                             SSTP_IOS_STAGE_SSTP_CONTROL,
                             "SSTP crypto binding failed");
            return;
        }
        sstp_pppd_get_ipv4(client->pppd, local, peer, dns1, dns2);
        session->ready = 1;
        sstp_ios_set_stage(SSTP_IOS_STAGE_APPLYING_SETTINGS);
        if (session->on_ready) {
            session->on_ready(session->ctx, local, peer, dns1, dns2);
        }
        break;
    }

    case SSTP_PPP_AUTH: {
        uint8_t skey[16];
        uint8_t rkey[16];
        sstp_ios_set_stage(SSTP_IOS_STAGE_PPP_AUTH);
        ret = sstp_chap_mppe_get(sstp_pppd_getchap(client->pppd),
                                 client->option.password, skey, rkey, 0);
        if (ret != 0) {
            log_err("Could not derive MPPE keys");
            sstp_ios_fail_ex(SSTP_IOS_ERR_MPPE_FAILED,
                             SSTP_IOS_STAGE_PPP_MPPE,
                             "Could not derive MPPE keys");
            return;
        }
        sstp_ios_set_stage(SSTP_IOS_STAGE_PPP_MPPE);
        sstp_state_mppe_keys(client->state, skey, rkey, 16);
        sstp_pppd_set_mppe_keys(client->pppd, skey, rkey);
        break;
    }

    default:
        break;
    }
}

static status_t ios_state_cb(void *arg, sstp_state_t event)
{
    sstp_client_st *client = arg;
    status_t ret = SSTP_OKAY;

    switch (event) {
    case SSTP_CALL_CONNECT:
        sstp_ios_set_stage(SSTP_IOS_STAGE_PPP_LCP);
        ret = sstp_pppd_create(&client->pppd, client->ev_base, client->stream,
                               (sstp_pppd_fn)ios_pppd_cb, client);
        if (ret != SSTP_OKAY) {
            sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL,
                             SSTP_IOS_STAGE_PPP_LCP,
                             "Could not create PPP context");
            return SSTP_FAIL;
        }
        sstp_pppd_set_ip_handler(client->pppd, ios_ip_handler, g_current);

        ret = sstp_pppd_start(client->pppd, &client->option, NULL);
        if (ret == SSTP_FAIL) {
            sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL,
                             SSTP_IOS_STAGE_PPP_LCP,
                             "Could not start PPP");
            return SSTP_FAIL;
        }

        sstp_state_set_forward(client->state, (sstp_state_forward_fn)sstp_pppd_send,
                               client->pppd);
        log_info("Started PPP Link Negotiation");
        return ret;

    case SSTP_CALL_ESTABLISHED:
        log_info("SSTP Connection Established");
        break;

    case SSTP_CALL_ABORT:
    default:
        if (client->pppd) {
            sstp_pppd_stop(client->pppd);
        }
        {
            const char *reason = sstp_state_reason(client->state);
            sstp_ios_fail_ex(SSTP_IOS_ERR_SSTP_CONTROL,
                             SSTP_IOS_STAGE_SSTP_CONTROL,
                             reason ? reason : "SSTP call aborted");
        }
        break;
    }
    return ret;
}

static void ios_http_done(void *arg, int status)
{
    sstp_client_st *client = arg;
    sstp_option_st *opts = &client->option;
    sstp_ios_session_t *session = g_current;
    int vopts = SSTP_VERIFY_NONE;

    if (status != SSTP_OKAY) {
        if (status == SSTP_TIMEOUT) {
            sstp_ios_fail_ex(SSTP_IOS_ERR_HTTP_UPGRADE,
                             SSTP_IOS_STAGE_HTTP_UPGRADE,
                             "HTTP SSTP upgrade timed out");
        } else {
            sstp_ios_fail_ex(SSTP_IOS_ERR_HTTP_UPGRADE,
                             SSTP_IOS_STAGE_HTTP_UPGRADE,
                             "HTTP handshake with SSTP server failed");
        }
        return;
    }

    sstp_http_free(client->http);
    client->http = NULL;

    /* SYSTEM trust was already evaluated via SecTrust right after TLS handshake. */
    if (session && session->tls_mode == SSTP_IOS_TLS_SYSTEM) {
        log_debug("Skipping post-HTTP OpenSSL verify (system mode uses SecTrust)");
        /* fall through to SSTP control */
    } else if (!session || session->tls_mode != SSTP_IOS_TLS_INSECURE_DEBUG) {
        const char *verify_host = opts->host ?: opts->server;
        log_debug("Post-HTTP OpenSSL verify for host=%s mode=%s",
                  verify_host ? verify_host : "(null)",
                  session ? ios_tls_mode_name(session->tls_mode) : "none");
        vopts = SSTP_VERIFY_CERT | SSTP_VERIFY_NAME;
        status = sstp_verify_cert(client->stream, verify_host, vopts);
        if (status != SSTP_OKAY) {
            sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT,
                             SSTP_IOS_STAGE_TCP_TLS,
                             "Server certificate verification failed (chain or hostname)");
            return;
        }
        if (session && session->tls_mode == SSTP_IOS_TLS_PINNED &&
            session->pin_sha256_hex[0]) {
            unsigned char hash[32];
            char hex[65];
            int i;
            int hlen = (int)sizeof(hash);
            if (sstp_get_cert_hash(client->stream, SSTP_PROTO_HASH_SHA256,
                                   hash, hlen) != SSTP_OKAY) {
                sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT,
                                 SSTP_IOS_STAGE_TCP_TLS,
                                 "Could not hash server certificate for pin check");
                return;
            }
            for (i = 0; i < 32; i++) {
                snprintf(hex + i * 2, 3, "%02x", hash[i]);
            }
            if (strcasecmp(hex, session->pin_sha256_hex) != 0) {
                sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT,
                                 SSTP_IOS_STAGE_TCP_TLS,
                                 "Server certificate pin mismatch");
                return;
            }
        }
    }

    sstp_ios_set_stage(SSTP_IOS_STAGE_SSTP_CONTROL);
    status = sstp_state_create(&client->state, client->stream, ios_state_cb,
                               client, SSTP_MODE_CLIENT);
    if (status != SSTP_OKAY) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_SSTP_CONTROL,
                         SSTP_IOS_STAGE_SSTP_CONTROL,
                         "Could not create SSTP state machine");
        return;
    }

    status = sstp_state_start(client->state);
    if (status == SSTP_FAIL) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_SSTP_CONTROL,
                         SSTP_IOS_STAGE_SSTP_CONTROL,
                         "Could not start SSTP state machine");
    }
}

static void ios_connected(sstp_stream_st *stream, sstp_buff_st *buf,
                          void *ctx, status_t status)
{
    sstp_client_st *client = ctx;
    status_t ret;
    (void)buf;

    if (status == SSTP_TIMEOUT) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TCP_TIMEOUT,
                         SSTP_IOS_STAGE_TCP_TLS,
                         "TCP/TLS connect timed out");
        return;
    }
    if (status != SSTP_CONNECTED) {
        sstp_ios_session_t *session = g_current;
        long vr = sstp_stream_verify_result(stream);
        /* SYSTEM mode defers chain trust to SecTrust; OpenSSL verify_result
         * is not authoritative and must not mask real handshake failures. */
        if (session && session->tls_mode == SSTP_IOS_TLS_SYSTEM) {
            log_info("TLS handshake failed in system mode (SecTrust not reached) verify=%ld",
                     vr);
            sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_HANDSHAKE,
                             SSTP_IOS_STAGE_TCP_TLS,
                             "Could not complete TLS handshake with SSTP server");
        } else if (vr != X509_V_OK && vr != X509_V_ERR_INVALID_CALL) {
            char msg[192];
            snprintf(msg, sizeof(msg), "Server certificate verification failed: %s",
                     X509_verify_cert_error_string(vr));
            log_info("TLS handshake/cert verify failed: %s", msg);
            sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_CERT,
                             SSTP_IOS_STAGE_TCP_TLS, msg);
        } else {
            log_info("TLS handshake failed verify=%ld", vr);
            sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_HANDSHAKE,
                             SSTP_IOS_STAGE_TCP_TLS,
                             "Could not complete TLS handshake with SSTP server");
        }
        return;
    }

    if (g_current && g_current->tls_mode == SSTP_IOS_TLS_SYSTEM) {
        const char *host = client->option.host ?: client->option.server;
        if (ios_evaluate_system_trust(stream, host) != 0) {
            return;
        }
    }

    sstp_ios_set_stage(SSTP_IOS_STAGE_HTTP_UPGRADE);
    ret = sstp_http_create(&client->http, client->host.name,
                           ios_http_done, client, SSTP_MODE_CLIENT);
    if (ret != SSTP_OKAY) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_HTTP_UPGRADE,
                         SSTP_IOS_STAGE_HTTP_UPGRADE,
                         "Could not create HTTP context");
        return;
    }

    ret = sstp_http_handshake(client->http, client->stream);
    log_debug("sstp_http_handshake returned %d", ret);
    if (ret != SSTP_OKAY && ret != SSTP_INPROG) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_HTTP_UPGRADE,
                         SSTP_IOS_STAGE_HTTP_UPGRADE,
                         "Could not start HTTP handshake");
    }
}

static status_t ios_lookup(const char *host, const char *port, sstp_peer_st *peer)
{
    struct addrinfo hints;
    struct addrinfo *list = NULL;
    struct addrinfo *ptr;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, port ? port : "443", &hints, &list);
    if (ret != 0 || !list) {
        return SSTP_FAIL;
    }

    for (ptr = list; ptr; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            memcpy(&peer->addr, ptr->ai_addr, ptr->ai_addrlen);
            peer->alen = (socklen_t)ptr->ai_addrlen;
            strncpy(peer->name, host, sizeof(peer->name) - 1);
            freeaddrinfo(list);
            return SSTP_OKAY;
        }
    }
    freeaddrinfo(list);
    return SSTP_FAIL;
}

sstp_ios_session_t *sstp_ios_session_create(sstp_ios_ready_fn on_ready,
                                            sstp_ios_packet_fn on_packet,
                                            sstp_ios_stage_fn on_stage,
                                            sstp_ios_fail_fn on_fail,
                                            void *ctx)
{
    sstp_ios_session_t *session = calloc(1, sizeof(*session));
    if (!session) return NULL;
    session->on_ready = on_ready;
    session->on_packet = on_packet;
    session->on_stage = on_stage;
    session->on_fail = on_fail;
    session->ctx = ctx;
    session->inject_fds[0] = session->inject_fds[1] = -1;
    session->stop_fds[0] = session->stop_fds[1] = -1;
    snprintf(session->stage, sizeof(session->stage), "%s", SSTP_IOS_STAGE_IDLE);
    session->tls_mode = SSTP_IOS_TLS_SYSTEM;
    return session;
}

int sstp_ios_session_start(sstp_ios_session_t *session,
                           const char *server,
                           const char *username,
                           const char *password)
{
    sstp_ios_start_params_t params;
    memset(&params, 0, sizeof(params));
    params.server = server;
    params.username = username;
    params.password = password;
    params.tls_mode = SSTP_IOS_TLS_SYSTEM;
    return sstp_ios_session_start_ex(session, &params);
}

int sstp_ios_session_start_ex(sstp_ios_session_t *session,
                              const sstp_ios_start_params_t *params)
{
    sstp_client_st *client;
    sstp_option_st *opt;
    char urlbuf[512];
    status_t ret;

    if (!session || !params || !params->server || !params->username || !params->password) {
        return -1;
    }

    g_current = session;
    client = &session->client;
    memset(client, 0, sizeof(*client));
    opt = &client->option;
    session->failed = 0;
    session->ready = 0;
    session->fail_code[0] = 0;
    session->fail_msg[0] = 0;
    session->tls_mode = params->tls_mode;
    free(session->ca_pem);
    session->ca_pem = NULL;
    session->ca_pem_len = 0;
    session->pin_sha256_hex[0] = 0;
    if (params->ca_pem && params->ca_pem_len > 0) {
        session->ca_pem = malloc(params->ca_pem_len + 1);
        if (!session->ca_pem) return -1;
        memcpy(session->ca_pem, params->ca_pem, params->ca_pem_len);
        session->ca_pem[params->ca_pem_len] = 0;
        session->ca_pem_len = params->ca_pem_len;
    }
    if (params->pin_sha256_hex && params->pin_sha256_hex[0]) {
        snprintf(session->pin_sha256_hex, sizeof(session->pin_sha256_hex),
                 "%s", params->pin_sha256_hex);
        /* Normalize to lowercase */
        {
            size_t i;
            for (i = 0; session->pin_sha256_hex[i]; i++) {
                session->pin_sha256_hex[i] = (char)tolower((unsigned char)session->pin_sha256_hex[i]);
            }
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#endif
    sstp_log_init("sstp-ios", SSTP_LOG_DEBUG, SSTP_OPT_STDERR | SSTP_OPT_LINENO);

    log_info("SSTP session start server=%s host=%s port=%s user=%s tls_mode=%s ca_pem=%s pin=%s",
             params->server ? params->server : "(null)",
             (params->server_host && params->server_host[0]) ? params->server_host : "(auto)",
             (params->server_port && params->server_port[0]) ? params->server_port : "(auto)",
             params->username,
             ios_tls_mode_name(params->tls_mode),
             (params->ca_pem && params->ca_pem_len > 0) ? "set" : "none",
             (params->pin_sha256_hex && params->pin_sha256_hex[0]) ? "set" : "none");

    {
        const char *endpoint_host = (params->server_host && params->server_host[0])
            ? params->server_host
            : params->server;
        opt->server = endpoint_host ? strdup(endpoint_host) : NULL;
    }
    opt->user = strdup(params->username);
    opt->password = strdup(params->password);
    /* CERTWARN only for explicit insecure debug; production rejects bad certs. */
    opt->enable = SSTP_OPT_NOLAUNCH | SSTP_OPT_NOPLUGIN |
                  SSTP_OPT_NODAEMON | SSTP_OPT_TLSEXT;
    if (session->tls_mode == SSTP_IOS_TLS_INSECURE_DEBUG) {
        opt->enable |= SSTP_OPT_CERTWARN;
    }

    if (params->server_host && params->server_host[0] &&
        params->server_port && params->server_port[0]) {
        snprintf(urlbuf, sizeof(urlbuf), "https://%s:%s/",
                 params->server_host, params->server_port);
    } else if (params->server_host && params->server_host[0]) {
        snprintf(urlbuf, sizeof(urlbuf), "https://%s/", params->server_host);
    } else {
        snprintf(urlbuf, sizeof(urlbuf), "https://%s/", params->server);
    }
    ret = sstp_url_parse(&client->url, urlbuf);
    if (ret != SSTP_OKAY) {
        const char *fallback_host = (params->server_host && params->server_host[0])
            ? params->server_host
            : params->server;
        const char *fallback_port = (params->server_port && params->server_port[0])
            ? params->server_port
            : "443";
        client->url = calloc(1, sizeof(*client->url));
        if (!client->url) return -1;
        client->url->host = strdup(fallback_host);
        client->url->schema = strdup("https");
        client->url->port = strdup(fallback_port);
        log_warn("URL parse failed for %s; using explicit host=%s port=%s",
                 urlbuf, fallback_host, fallback_port);
    }
    if (client->url && !client->url->port) {
        client->url->port = (char *)"443";
    }
    opt->host = client->url->host;
    log_info("Parsed SSTP URL host=%s port=%s schema=%s",
             client->url->host ?: "(null)",
             client->url->port ?: "(null)",
             client->url->schema ?: "(null)");

    client->ev_base = event_base_new();
    if (!client->ev_base) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL, SSTP_IOS_STAGE_IDLE,
                         "Could not create event base");
        return -1;
    }

    if (ios_make_nonblock_pipe(session->inject_fds) != 0) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL, SSTP_IOS_STAGE_IDLE,
                         "Could not create inject pipe");
        return -1;
    }
    if (ios_make_nonblock_pipe(session->stop_fds) != 0) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL, SSTP_IOS_STAGE_IDLE,
                         "Could not create stop pipe");
        return -1;
    }

    session->inject_ev = event_new(client->ev_base, session->inject_fds[0],
                                   EV_READ | EV_PERSIST, ios_inject_cb, session);
    session->stop_ev = event_new(client->ev_base, session->stop_fds[0],
                                 EV_READ | EV_PERSIST, ios_stop_cb, session);
    if (!session->inject_ev || !session->stop_ev) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_INTERNAL, SSTP_IOS_STAGE_IDLE,
                         "Could not create inject/stop events");
        return -1;
    }
    event_add(session->inject_ev, NULL);
    event_add(session->stop_ev, NULL);

    if (ios_init_ssl(session) != SSTP_OKAY) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_HANDSHAKE, SSTP_IOS_STAGE_TCP_TLS,
                         "Could not initialize SSL");
        return -1;
    }

    sstp_ios_set_stage(SSTP_IOS_STAGE_RESOLVING);
    if (ios_lookup(client->url->host, client->url->port, &client->host) != SSTP_OKAY) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_DNS_RESOLVE, SSTP_IOS_STAGE_RESOLVING,
                         "Could not resolve SSTP server");
        return -1;
    }

    sstp_ios_set_stage(SSTP_IOS_STAGE_TCP_TLS);
    ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx, opt);
    if (ret != SSTP_OKAY) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TLS_HANDSHAKE, SSTP_IOS_STAGE_TCP_TLS,
                         "Could not create SSL stream");
        return -1;
    }

    ret = sstp_stream_connect(client->stream,
                              (struct sockaddr *)&client->host.addr,
                              client->host.alen,
                              ios_connected, client, 60);
    if (ret != SSTP_OKAY && ret != SSTP_INPROG) {
        sstp_ios_fail_ex(SSTP_IOS_ERR_TCP_TIMEOUT, SSTP_IOS_STAGE_TCP_TLS,
                         "Could not start TCP/TLS connect");
        return -1;
    }

    return 0;
}

int sstp_ios_session_write_ip(sstp_ios_session_t *session,
                              const uint8_t *ip_packet,
                              size_t len)
{
    uint8_t hdr[4];
    if (!session || session->inject_fds[1] < 0 || !ip_packet || len == 0 || len > 2000) {
        return -1;
    }
    if (!session->ready) {
        return -1;
    }

    hdr[0] = (uint8_t)((len >> 24) & 0xff);
    hdr[1] = (uint8_t)((len >> 16) & 0xff);
    hdr[2] = (uint8_t)((len >> 8) & 0xff);
    hdr[3] = (uint8_t)(len & 0xff);

    if (write(session->inject_fds[1], hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        return -1;
    }
    if (write(session->inject_fds[1], ip_packet, len) != (ssize_t)len) {
        return -1;
    }
    return 0;
}

void sstp_ios_session_run(sstp_ios_session_t *session)
{
    if (!session || !session->client.ev_base) return;
    g_current = session;
    session->escape_set = 1;
    if (setjmp(session->escape) == 0) {
        event_base_dispatch(session->client.ev_base);
    }
    session->escape_set = 0;
}

void sstp_ios_session_stop(sstp_ios_session_t *session)
{
    char b = 1;
    if (!session) return;
    snprintf(session->stage, sizeof(session->stage), "%s", SSTP_IOS_STAGE_DISCONNECTING);
    if (session->client.pppd) {
        sstp_pppd_stop(session->client.pppd);
    }
    if (session->stop_fds[1] >= 0) {
        (void)write(session->stop_fds[1], &b, 1);
    } else if (session->client.ev_base) {
        event_base_loopbreak(session->client.ev_base);
    }
}

void sstp_ios_session_free(sstp_ios_session_t *session)
{
    sstp_client_st *client;
    if (!session) return;
    client = &session->client;

    if (session->inject_ev) {
        event_free(session->inject_ev);
        session->inject_ev = NULL;
    }
    if (session->stop_ev) {
        event_free(session->stop_ev);
        session->stop_ev = NULL;
    }
    if (session->inject_fds[0] >= 0) close(session->inject_fds[0]);
    if (session->inject_fds[1] >= 0) close(session->inject_fds[1]);
    if (session->stop_fds[0] >= 0) close(session->stop_fds[0]);
    if (session->stop_fds[1] >= 0) close(session->stop_fds[1]);
    session->inject_fds[0] = session->inject_fds[1] = -1;
    session->stop_fds[0] = session->stop_fds[1] = -1;

    if (client->state) sstp_state_free(client->state);
    if (client->http) sstp_http_free(client->http);
    if (client->pppd) sstp_pppd_free(client->pppd);
    if (client->stream) sstp_stream_destroy(client->stream);
    if (client->ssl_ctx) SSL_CTX_free(client->ssl_ctx);
    if (client->ev_base) event_base_free(client->ev_base);
    if (client->url) sstp_url_free(client->url);
    free(client->option.server);
    free(client->option.user);
    if (client->option.password) {
        memset(client->option.password, 0, strlen(client->option.password));
        free(client->option.password);
    }
    free(session->ca_pem);

    if (g_current == session) g_current = NULL;
    free(session);
}

const char *sstp_ios_session_stage(const sstp_ios_session_t *session)
{
    return session ? session->stage : SSTP_IOS_STAGE_IDLE;
}

const char *sstp_ios_session_last_error_code(const sstp_ios_session_t *session)
{
    if (!session || !session->fail_code[0]) return NULL;
    return session->fail_code;
}

const char *sstp_ios_session_last_error_message(const sstp_ios_session_t *session)
{
    if (!session || !session->fail_msg[0]) return NULL;
    return session->fail_msg;
}

int sstp_ios_session_is_ready(const sstp_ios_session_t *session)
{
    return session && session->ready ? 1 : 0;
}
