//
//  VPNManager.h
//  com.vn.sstp
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

extern NSNotificationName const VPNManagerStatusDidChangeNotification;

@interface VPNManager : NSObject

@property (nonatomic, readonly) NEVPNStatus status;
@property (nonatomic, readonly, copy) NSString *statusText;
@property (nonatomic, readonly, getter=isConnected) BOOL connected;
@property (nonatomic, readonly, getter=isConnecting) BOOL connecting;

+ (instancetype)sharedManager;

- (void)reloadWithCompletion:(void (^)(NSError * _Nullable error))completion;

- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                         completion:(void (^)(NSError * _Nullable error))completion;

- (void)connectWithCompletion:(void (^)(NSError * _Nullable error))completion;
- (void)disconnect;

@end

NS_ASSUME_NONNULL_END
