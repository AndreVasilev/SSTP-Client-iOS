//
//  KeychainHelper.h
//  com.vn.sstp
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface KeychainHelper : NSObject

+ (BOOL)setPassword:(NSString *)password forAccount:(NSString *)account error:(NSError * _Nullable * _Nullable)error;
+ (nullable NSString *)passwordForAccount:(NSString *)account error:(NSError * _Nullable * _Nullable)error;
+ (nullable NSData *)passwordReferenceForAccount:(NSString *)account error:(NSError * _Nullable * _Nullable)error;
+ (BOOL)deletePasswordForAccount:(NSString *)account error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
