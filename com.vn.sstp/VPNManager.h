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

/** Last known SSTP stage string (idle/resolving/tcp_tls/...). */
@property (nonatomic, readonly, copy) NSString *stage;
/** Machine-readable last error code, if any. */
@property (nonatomic, readonly, copy, nullable) NSString *lastErrorCode;
@property (nonatomic, readonly, copy, nullable) NSString *lastErrorMessage;
@property (nonatomic, readonly, copy, nullable) NSString *lastErrorHint;

+ (instancetype)sharedManager;

- (void)reloadWithCompletion:(void (^)(NSError * _Nullable error))completion;

- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                         completion:(void (^)(NSError * _Nullable error))completion;

/** Advanced TLS trust options (optional). mode: system|custom_ca|pinned|(debug)insecure_debug */
- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                            tlsMode:(NSString * _Nullable)tlsMode
                              caPem:(NSString * _Nullable)caPem
                          pinSha256:(NSString * _Nullable)pinSha256
                         completion:(void (^)(NSError * _Nullable error))completion;

- (void)connectWithCompletion:(void (^)(NSError * _Nullable error))completion;
- (void)disconnect;

/** Refresh stage/lastError from extension or App Group. */
- (void)refreshTunnelStatusWithCompletion:(void (^ _Nullable)(void))completion;

@end

NS_ASSUME_NONNULL_END
