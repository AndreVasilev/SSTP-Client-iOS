/*!
 * URL parser tests used by iOS session start (https://host/).
 */
#include "config.h"
#include "harness.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sstp-common.h"
#include "sstp-util.h"

int main(void)
{
    sstp_url_st *url = NULL;
    status_t st;

    st = sstp_url_parse(&url, "https://vpn.example.com/");
    TEST_ASSERT(st == SSTP_OKAY, "parse https host");
    TEST_ASSERT_STREQ(url->schema, "https", "schema");
    TEST_ASSERT_STREQ(url->host, "vpn.example.com", "host");
    TEST_ASSERT(url->port == NULL || strcmp(url->port, "443") == 0,
                "default/https port");
    sstp_url_free(url);

    st = sstp_url_parse(&url, "https://10.0.0.5:8443/path");
    TEST_ASSERT(st == SSTP_OKAY, "parse host:port/path");
    TEST_ASSERT_STREQ(url->host, "10.0.0.5", "ipv4 host");
    TEST_ASSERT_STREQ(url->port, "8443", "explicit port");
    TEST_ASSERT_STREQ(url->path, "path", "path");
    sstp_url_free(url);

    st = sstp_url_parse(&url, "192.168.1.1:8443");
    TEST_ASSERT(st == SSTP_OKAY, "parse bare ipv4:port");
    TEST_ASSERT_STREQ(url->host, "192.168.1.1", "bare host");
    TEST_ASSERT_STREQ(url->port, "8443", "bare port");
    sstp_url_free(url);

    st = sstp_url_parse(&url, "192.168.1.1:84433");
    TEST_ASSERT(st == SSTP_FAIL, "reject invalid port");

    st = sstp_url_parse(&url, "https://user:secret@server.sstp-test.com:443/some/path");
    TEST_ASSERT(st == SSTP_OKAY, "parse user:pass");
    TEST_ASSERT_STREQ(url->user, "user", "user");
    TEST_ASSERT_STREQ(url->password, "secret", "password");
    TEST_ASSERT_STREQ(url->host, "server.sstp-test.com", "auth host");
    sstp_url_free(url);

    return test_report("url");
}
