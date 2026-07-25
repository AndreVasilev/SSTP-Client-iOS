/*!
 * Buffer helper tests.
 */
#include "config.h"
#include "harness.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sstp-common.h"
#include "sstp-buff.h"

int main(void)
{
    sstp_buff_st *buf = NULL;
    status_t st;

    st = sstp_buff_create(&buf, 128);
    TEST_ASSERT(st == SSTP_OKAY, "sstp_buff_create succeeds");
    TEST_ASSERT(buf != NULL, "buffer pointer set");
    TEST_ASSERT(buf->max == 128, "buffer max size");
    TEST_ASSERT(buf->len == 0, "buffer starts empty");
    TEST_ASSERT(buf->off == 0, "buffer offset starts at 0");

    st = sstp_buff_space(buf, 64);
    TEST_ASSERT(st == SSTP_OKAY, "space available for 64 bytes");

    st = sstp_buff_space(buf, 200);
    TEST_ASSERT(st != SSTP_OKAY, "space rejected when over capacity");

    memcpy(buf->data, "hello", 5);
    buf->len = 5;
    TEST_ASSERT(buf->len == 5, "length updated");

    sstp_buff_destroy(buf);
    sstp_buff_destroy(NULL); /* must not crash */
    TEST_ASSERT(1, "destroy handles NULL");

    return test_report("buff");
}
