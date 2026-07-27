//
//  KeychainHelper.m
//  com.vn.sstp
//

#import "KeychainHelper.h"
#import <Security/Security.h>

static NSString * const kKeychainService = @"ru.altatec.sstp-client.vpn";

@implementation KeychainHelper

+ (NSMutableDictionary *)identityQueryForAccount:(NSString *)account {
    /* Search/delete query: only identity attributes.
     * Do NOT include kSecAttrAccessible here — it prevents matching items
     * stored with a different accessibility and leads to duplicate-add failures. */
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account,
    } mutableCopy];
}

+ (NSString *)statusMessage:(OSStatus)status {
    NSString *sys = nil;
#if __IPHONE_OS_VERSION_MIN_REQUIRED
    if (@available(iOS 11.3, *)) {
        sys = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
    }
#endif
    if (sys.length > 0) {
        return [NSString stringWithFormat:@"%@ (%d)", sys, (int)status];
    }
    return [NSString stringWithFormat:@"OSStatus %d", (int)status];
}

+ (BOOL)setPassword:(NSString *)password forAccount:(NSString *)account error:(NSError **)error {
    if (password.length == 0 || account.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecParam userInfo:@{
                NSLocalizedDescriptionKey: @"Пустой пароль или account для Keychain"
            }];
        }
        return NO;
    }

    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecParam userInfo:@{
                NSLocalizedDescriptionKey: @"Пароль нельзя закодировать в UTF-8"
            }];
        }
        return NO;
    }

    NSDictionary *identity = [self identityQueryForAccount:account];

    // Best-effort delete of any previous item (ignore not-found).
    SecItemDelete((__bridge CFDictionaryRef)identity);

    NSMutableDictionary *add = [identity mutableCopy];
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    if (status == errSecDuplicateItem) {
        // Item still present (e.g. different accessibility) — update in place.
        NSDictionary *attrs = @{
            (__bridge id)kSecValueData: data,
            (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
        };
        status = SecItemUpdate((__bridge CFDictionaryRef)identity,
                               (__bridge CFDictionaryRef)attrs);
    }

    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"Не удалось сохранить пароль в Keychain: %@",
                    [self statusMessage:status]]
            }];
        }
        return NO;
    }
    return YES;
}

+ (NSString *)passwordForAccount:(NSString *)account error:(NSError **)error {
    NSMutableDictionary *query = [self identityQueryForAccount:account];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) {
        return nil;
    }
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"Не удалось прочитать пароль из Keychain: %@",
                    [self statusMessage:status]]
            }];
        }
        return nil;
    }

    NSData *data = (__bridge_transfer NSData *)result;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSData *)passwordReferenceForAccount:(NSString *)account error:(NSError **)error {
    NSMutableDictionary *query = [self identityQueryForAccount:account];
    query[(__bridge id)kSecReturnPersistentRef] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) {
        return nil;
    }
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"Не удалось получить ссылку на пароль: %@",
                    [self statusMessage:status]]
            }];
        }
        return nil;
    }
    return (__bridge_transfer NSData *)result;
}

+ (BOOL)deletePasswordForAccount:(NSString *)account error:(NSError **)error {
    NSDictionary *query = [self identityQueryForAccount:account];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"Не удалось удалить пароль из Keychain: %@",
                    [self statusMessage:status]]
            }];
        }
        return NO;
    }
    return YES;
}

@end
