//
//  KeychainHelper.m
//  com.vn.sstp
//

#import "KeychainHelper.h"
#import <Security/Security.h>

static NSString * const kKeychainService = @"ru.altatec.sstp-client.vpn";

@implementation KeychainHelper

+ (NSMutableDictionary *)baseQueryForAccount:(NSString *)account {
    /* Access group comes from the shared keychain-access-groups entitlement
     * (first entry) so the Packet Tunnel can resolve passwordReference. */
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    } mutableCopy];
}

+ (BOOL)setPassword:(NSString *)password forAccount:(NSString *)account error:(NSError **)error {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query = [self baseQueryForAccount:account];

    SecItemDelete((__bridge CFDictionaryRef)query);

    query[(__bridge id)kSecValueData] = data;

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:@{
                NSLocalizedDescriptionKey: @"Не удалось сохранить пароль в Keychain"
            }];
        }
        return NO;
    }
    return YES;
}

+ (NSString *)passwordForAccount:(NSString *)account error:(NSError **)error {
    NSMutableDictionary *query = [self baseQueryForAccount:account];
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
                NSLocalizedDescriptionKey: @"Не удалось прочитать пароль из Keychain"
            }];
        }
        return nil;
    }

    NSData *data = (__bridge_transfer NSData *)result;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSData *)passwordReferenceForAccount:(NSString *)account error:(NSError **)error {
    NSMutableDictionary *query = [self baseQueryForAccount:account];
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
                NSLocalizedDescriptionKey: @"Не удалось получить ссылку на пароль"
            }];
        }
        return nil;
    }
    return (__bridge_transfer NSData *)result;
}

+ (BOOL)deletePasswordForAccount:(NSString *)account error:(NSError **)error {
    NSMutableDictionary *query = [self baseQueryForAccount:account];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        }
        return NO;
    }
    return YES;
}

@end
