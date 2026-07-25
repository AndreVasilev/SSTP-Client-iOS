/*!
 * @file sstp-ios.c
 * @brief SSTP session runner for iOS Packet Tunnel Provider.
 */

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "sstp-client.h"
#include "sstp-http.h"
#include "sstp-ios.h"
#include "sstp-private.h"

void sstp_pppd_set_ip_handler(sstp_pppd_st *ctx, void (*fn)(void *, const uint8_t *, int), void *arg);
void sstp_pppd_set_mppe_keys(sstp_pppd_st *ctx, const uint8_t skey[16], const uint8_t rkey[16]);
status_t sstp_pppd_send_ip(sstp_pppd_st *ctx, const uint8_t *ip, int len);
void sstp_pppd_get_ipv4(sstp_pppd_st *ctx, char local[16], char peer[16], char dns1[16], char dns2[16]);

struct sstp_ios_session {
    sstp_client_st client;
    sstp_ios_ready_fn on_ready;
    sstp_ios_packet_fn on_packet;
    sstp_ios_fail_fn on_fail;
    void *ctx;
    int failed;
    int ready;
    char fail_msg[256];
    jmp_buf escape;
    int escape_set;

    /* Cross-thread IP injection into the libevent loop */
    int inject_fds[2];
    event_st *inject_ev;
    int stop_fds[2];
    event_st *stop_ev;
};

static sstp_ios_session_t *g_current;

void sstp_ios_fail(const char *message)
{
    if (!g_current) return;
    g_current->failed = 1;
    snprintf(g_current->fail_msg, sizeof(g_current->fail_msg), "%s",
             message ? message : "SSTP failure");
    if (g_current->on_fail) {
        g_current->on_fail(g_current->ctx, g_current->fail_msg);
    }
    if (g_current->client.ev_base) {
        event_base_loopbreak(g_current->client.ev_base);
    }
    if (g_current->escape_set) {
        longjmp(g_current->escape, 1);
    }
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
            /* Drain invalid length */
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

static void ios_pppd_cb(sstp_client_st *client, sstp_pppd_event_t ev)
{
    sstp_ios_session_t *session = g_current;
    int ret;

    switch (ev) {
    case SSTP_PPP_START:
        sstp_state_resume_recv(client->state);
        break;

    case SSTP_PPP_DOWN:
        log_err("PPP terminated");
        sstp_ios_fail("PPP connection terminated");
        break;

    case SSTP_PPP_UP: {
        char local[16], peer[16], dns1[16], dns2[16];
        ret = sstp_state_accept(client->state);
        if (ret == SSTP_FAIL) {
            sstp_ios_fail("SSTP Connected (crypto binding) failed");
            return;
        }
        sstp_pppd_get_ipv4(client->pppd, local, peer, dns1, dns2);
        session->ready = 1;
        if (session->on_ready) {
            session->on_ready(session->ctx, local, peer, dns1, dns2);
        }
        break;
    }

    case SSTP_PPP_AUTH: {
        uint8_t skey[16];
        uint8_t rkey[16];
        ret = sstp_chap_mppe_get(sstp_pppd_getchap(client->pppd),
                                 client->option.password, skey, rkey, 0);
        if (ret != 0) {
            log_err("Could not derive MPPE keys");
            return;
        }
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
        ret = sstp_pppd_create(&client->pppd, client->ev_base, client->stream,
                               (sstp_pppd_fn)ios_pppd_cb, client);
        if (ret != SSTP_OKAY) {
            sstp_ios_fail("Could not create PPP context");
            return SSTP_FAIL;
        }
        sstp_pppd_set_ip_handler(client->pppd, ios_ip_handler, g_current);

        ret = sstp_pppd_start(client->pppd, &client->option, NULL);
        if (ret == SSTP_FAIL) {
            sstp_ios_fail("Could not start PPP");
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
            sstp_ios_fail(reason ? reason : "SSTP call aborted");
        }
        break;
    }
    return ret;
}

static void ios_http_done(void *arg, int status)
{
    sstp_client_st *client = arg;
    sstp_option_st *opts = &client->option;
    int vopts = SSTP_VERIFY_NONE;

    if (status != SSTP_OKAY) {
        sstp_ios_fail("HTTP handshake with SSTP server failed");
        return;
    }

    sstp_http_free(client->http);
    client->http = NULL;

    vopts = SSTP_VERIFY_NAME;
    status = sstp_verify_cert(client->stream, opts->host ?: opts->server, vopts);
    if (status != SSTP_OKAY) {
        log_warn("Server certificate verification failed, continuing");
    }

    status = sstp_state_create(&client->state, client->stream, ios_state_cb,
                               client, SSTP_MODE_CLIENT);
    if (status != SSTP_OKAY) {
        sstp_ios_fail("Could not create SSTP state machine");
        return;
    }

    status = sstp_state_start(client->state);
    if (status == SSTP_FAIL) {
        sstp_ios_fail("Could not start SSTP state machine");
    }
}

static void ios_connected(sstp_stream_st *stream, sstp_buff_st *buf,
                          void *ctx, status_t status)
{
    sstp_client_st *client = ctx;
    status_t ret;
    (void)stream;
    (void)buf;

    if (status != SSTP_CONNECTED) {
        sstp_ios_fail("Could not connect to SSTP server");
        return;
    }

    ret = sstp_http_create(&client->http, client->host.name,
                           ios_http_done, client, SSTP_MODE_CLIENT);
    if (ret != SSTP_OKAY) {
        sstp_ios_fail("Could not create HTTP context");
        return;
    }

    ret = sstp_http_handshake(client->http, client->stream);
    if (ret != SSTP_OKAY && ret != SSTP_INPROG) {
        sstp_ios_fail("Could not start HTTP handshake");
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

static status_t ios_init_ssl(sstp_client_st *client)
{
    client->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!client->ssl_ctx) {
        return SSTP_FAIL;
    }
    SSL_CTX_set_options(client->ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(client->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
    SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_NONE, NULL);
    return SSTP_OKAY;
}

sstp_ios_session_t *sstp_ios_session_create(sstp_ios_ready_fn on_ready,
                                            sstp_ios_packet_fn on_packet,
                                            sstp_ios_fail_fn on_fail,
                                            void *ctx)
{
    sstp_ios_session_t *session = calloc(1, sizeof(*session));
    if (!session) return NULL;
    session->on_ready = on_ready;
    session->on_packet = on_packet;
    session->on_fail = on_fail;
    session->ctx = ctx;
    session->inject_fds[0] = session->inject_fds[1] = -1;
    session->stop_fds[0] = session->stop_fds[1] = -1;
    return session;
}

int sstp_ios_session_start(sstp_ios_session_t *session,
                           const char *server,
                           const char *username,
                           const char *password)
{
    sstp_client_st *client;
    sstp_option_st *opt;
    char urlbuf[512];
    status_t ret;

    if (!session || !server || !username || !password) {
        return -1;
    }

    g_current = session;
    client = &session->client;
    memset(client, 0, sizeof(*client));
    opt = &client->option;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#endif
    sstp_log_init("sstp-ios", SSTP_LOG_INFO, SSTP_OPT_STDERR | SSTP_OPT_LINENO);

    opt->server = strdup(server);
    opt->user = strdup(username);
    opt->password = strdup(password);
    opt->enable = SSTP_OPT_NOLAUNCH | SSTP_OPT_NOPLUGIN | SSTP_OPT_CERTWARN |
                  SSTP_OPT_NODAEMON | SSTP_OPT_TLSEXT;

    snprintf(urlbuf, sizeof(urlbuf), "https://%s/", server);
    ret = sstp_url_parse(&client->url, urlbuf);
    if (ret != SSTP_OKAY) {
        client->url = calloc(1, sizeof(*client->url));
        if (!client->url) return -1;
        client->url->host = strdup(server);
        client->url->schema = strdup("https");
        client->url->port = strdup("443");
    }
    if (client->url && !client->url->port) {
        /* Literal is fine: sstp_url_free only releases url->ptr */
        client->url->port = (char *)"443";
    }
    opt->host = client->url->host;

    client->ev_base = event_base_new();
    if (!client->ev_base) {
        sstp_ios_fail("Could not create event base");
        return -1;
    }

    if (ios_make_nonblock_pipe(session->inject_fds) != 0) {
        sstp_ios_fail("Could not create inject pipe");
        return -1;
    }
    if (ios_make_nonblock_pipe(session->stop_fds) != 0) {
        sstp_ios_fail("Could not create stop pipe");
        return -1;
    }

    session->inject_ev = event_new(client->ev_base, session->inject_fds[0],
                                   EV_READ | EV_PERSIST, ios_inject_cb, session);
    session->stop_ev = event_new(client->ev_base, session->stop_fds[0],
                                 EV_READ | EV_PERSIST, ios_stop_cb, session);
    if (!session->inject_ev || !session->stop_ev) {
        sstp_ios_fail("Could not create inject/stop events");
        return -1;
    }
    event_add(session->inject_ev, NULL);
    event_add(session->stop_ev, NULL);

    if (ios_init_ssl(client) != SSTP_OKAY) {
        sstp_ios_fail("Could not initialize SSL");
        return -1;
    }

    if (ios_lookup(client->url->host, client->url->port, &client->host) != SSTP_OKAY) {
        sstp_ios_fail("Could not resolve SSTP server");
        return -1;
    }

    ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx, opt);
    if (ret != SSTP_OKAY) {
        sstp_ios_fail("Could not create SSL stream");
        return -1;
    }

    ret = sstp_stream_connect(client->stream,
                              (struct sockaddr *)&client->host.addr,
                              client->host.alen,
                              ios_connected, client, 60);
    if (ret != SSTP_OKAY && ret != SSTP_INPROG) {
        sstp_ios_fail("Could not start TCP/TLS connect");
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
    free(client->option.password);

    if (g_current == session) g_current = NULL;
    free(session);
}
