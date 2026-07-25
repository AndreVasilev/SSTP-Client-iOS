/*!
 * HDLC / PPP FCS encode-decode roundtrip tests.
 */
#include "config.h"
#include "harness.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sstp-common.h"
#include "sstp-fcs.h"

int main(void)
{
    /* LCP Configure-Request style PPP payload (proto + data) */
    const unsigned char payload[] = {
        0xc0, 0x21, 0x01, 0x01, 0x00, 0x08, 0x01, 0x04, 0x05, 0x78
    };
    unsigned char encoded[256];
    unsigned char decoded[256];
    int elen = (int)sizeof(encoded);
    int dlen = (int)sizeof(decoded);
    int in_len;
    status_t st;
    uint16_t fcs;

    fcs = sstp_frame_check(PPPINITFCS16, payload, (int)sizeof(payload));
    TEST_ASSERT(fcs != PPPINITFCS16, "FCS changes for non-empty input");

    st = sstp_frame_encode(payload, (int)sizeof(payload), encoded, &elen);
    TEST_ASSERT(st == SSTP_OKAY, "sstp_frame_encode succeeds");
    TEST_ASSERT(elen > (int)sizeof(payload), "encoded frame larger than payload");
    TEST_ASSERT(encoded[0] == HDLC_FLAG, "encoded starts with flag");
    TEST_ASSERT(encoded[elen - 1] == HDLC_FLAG, "encoded ends with flag");

    in_len = elen;
    st = sstp_frame_decode(encoded, &in_len, decoded, &dlen);
    TEST_ASSERT(st == SSTP_OKAY, "sstp_frame_decode succeeds");
    TEST_ASSERT(dlen == (int)sizeof(payload), "decoded length matches payload");
    TEST_ASSERT_EQ_MEM(decoded, payload, sizeof(payload), "decode roundtrip");

    return test_report("fcs");
}
