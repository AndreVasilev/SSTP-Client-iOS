/*!
 * @file sstp-ios-trust.m
 * @brief SecTrust evaluation for SSTP System TLS mode.
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <string.h>

#include "sstp-ios-trust.h"

static void trust_set_err(char *errmsg, size_t errmsg_len, NSString *msg)
{
    if (!errmsg || errmsg_len == 0) {
        return;
    }
    if (!msg) {
        errmsg[0] = '\0';
        return;
    }
    NSString *trimmed = [msg length] > (errmsg_len - 1)
        ? [msg substringToIndex:(errmsg_len - 1)]
        : msg;
    strncpy(errmsg, trimmed.UTF8String, errmsg_len - 1);
    errmsg[errmsg_len - 1] = '\0';
}

int sstp_ios_sec_trust_evaluate(const unsigned char *const *ders,
                                const size_t *lens,
                                size_t count,
                                const char *hostname,
                                char *errmsg,
                                size_t errmsg_len)
{
    if (!ders || !lens || count == 0 || !hostname || !hostname[0]) {
        trust_set_err(errmsg, errmsg_len, @"Missing certificate chain or hostname");
        return -1;
    }

    @autoreleasepool {
        NSMutableArray *certs = [NSMutableArray arrayWithCapacity:count];
        for (size_t i = 0; i < count; i++) {
            if (!ders[i] || lens[i] == 0) {
                trust_set_err(errmsg, errmsg_len, @"Empty certificate in peer chain");
                return -1;
            }
            NSData *der = [NSData dataWithBytes:ders[i] length:lens[i]];
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
            if (!cert) {
                trust_set_err(errmsg, errmsg_len, @"Could not parse peer certificate DER");
                return -1;
            }
            [certs addObject:(__bridge_transfer id)cert];
        }

        NSString *host = [NSString stringWithUTF8String:hostname];
        if (!host.length) {
            trust_set_err(errmsg, errmsg_len, @"Invalid hostname for trust evaluation");
            return -1;
        }

        SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)host);
        if (!policy) {
            trust_set_err(errmsg, errmsg_len, @"Could not create SSL trust policy");
            return -1;
        }

        SecTrustRef trust = NULL;
        OSStatus createStatus = SecTrustCreateWithCertificates(
            (__bridge CFArrayRef)certs, policy, &trust);
        CFRelease(policy);
        if (createStatus != errSecSuccess || !trust) {
            trust_set_err(errmsg, errmsg_len, @"Could not create SecTrust for peer chain");
            return -1;
        }

        CFErrorRef error = NULL;
        bool ok = SecTrustEvaluateWithError(trust, &error);
        if (!ok) {
            NSString *reason = @"iOS system trust rejected server certificate";
            if (error) {
                NSError *nserr = (__bridge_transfer NSError *)error;
                if (nserr.localizedDescription.length > 0) {
                    reason = [NSString stringWithFormat:
                              @"iOS system trust rejected server certificate: %@",
                              nserr.localizedDescription];
                }
            }
            NSLog(@"[SSTP SecTrust] FAIL host=%@ chain=%zu reason=%@",
                  host, count, reason);
            trust_set_err(errmsg, errmsg_len, reason);
            CFRelease(trust);
            return -1;
        }

        NSLog(@"[SSTP SecTrust] OK host=%@ chain=%zu", host, count);

        CFRelease(trust);
        if (errmsg && errmsg_len > 0) {
            errmsg[0] = '\0';
        }
        return 0;
    }
}
