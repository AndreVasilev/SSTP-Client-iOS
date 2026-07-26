//
//  PacketTunnelProvider.m
//  tunnel
//

#import "PacketTunnelProvider.h"
#import "sstp-ios.h"
#import "../shared/SSTPShared.h"
#import <Security/Security.h>
#import <string.h>

static const NSInteger kSSTPMaxReconnectAttempts = 3;
static const NSTimeInterval kSSTPStopTimeoutSeconds = 5.0;

@interface PacketTunnelProvider ()
@property (nonatomic, assign) sstp_ios_session_t *session;
@property (nonatomic, strong) NSThread *workerThread;
@property (nonatomic, copy) void (^pendingStartHandler)(NSError * _Nullable);
@property (nonatomic, assign) BOOL packetLoopRunning;
@property (nonatomic, assign) BOOL userStopRequested;
@property (nonatomic, assign) BOOL startCompletionCalled;
@property (nonatomic, assign) NSUInteger sessionGeneration;
@property (nonatomic, copy) NSString *currentStage;
@property (nonatomic, copy, nullable) NSString *lastErrorCode;
@property (nonatomic, copy, nullable) NSString *lastErrorMessage;
@property (nonatomic, copy) NSString *server;
@property (nonatomic, copy) NSString *username;
@property (nonatomic, copy) NSString *password;
@property (nonatomic, assign) sstp_ios_tls_mode_t tlsMode;
@property (nonatomic, copy, nullable) NSString *caPem;
@property (nonatomic, copy, nullable) NSString *pinSha256;
@property (nonatomic, assign) NSInteger reconnectAttempt;
@property (nonatomic, assign) BOOL reconnectScheduled;
@end

@implementation PacketTunnelProvider

#pragma mark - C callbacks

static void on_stage(void *ctx, const char *stage)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    NSString *text = [NSString stringWithUTF8String:stage ?: SSTP_IOS_STAGE_IDLE];
    dispatch_async(dispatch_get_main_queue(), ^{
        provider.currentStage = text;
        [provider persistStatus];
    });
}

static void on_ready(void *ctx, const char *local_ip, const char *gateway_ip,
                     const char *dns1, const char *dns2)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    NSString *local = [NSString stringWithUTF8String:local_ip ?: "10.0.0.2"];
    NSString *gateway = [NSString stringWithUTF8String:gateway_ip ?: "10.0.0.1"];
    NSString *d1 = [NSString stringWithUTF8String:dns1 ?: "8.8.8.8"];
    NSString *d2 = [NSString stringWithUTF8String:dns2 ?: "8.8.4.4"];
    NSUInteger generation = provider.sessionGeneration;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (provider.sessionGeneration != generation || provider.userStopRequested) {
            return;
        }
        provider.reconnectAttempt = 0;
        provider.currentStage = @(SSTP_IOS_STAGE_APPLYING_SETTINGS);
        [provider persistStatus];
        [provider applyTunnelSettingsWithLocalIP:local gateway:gateway dns1:d1 dns2:d2 generation:generation];
    });
}

static void on_packet(void *ctx, const uint8_t *ip_packet, size_t len)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    if (!ip_packet || len == 0) return;
    NSData *data = [NSData dataWithBytes:ip_packet length:len];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!provider.packetLoopRunning || !provider.session) return;
        [provider.packetFlow writePackets:@[data] withProtocols:@[@(AF_INET)]];
    });
}

static void on_fail(void *ctx, const char *code, const char *stage, const char *message)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    NSString *errCode = [NSString stringWithUTF8String:code ?: SSTP_IOS_ERR_INTERNAL];
    NSString *errStage = [NSString stringWithUTF8String:stage ?: SSTP_IOS_STAGE_ERROR];
    NSString *text = [NSString stringWithUTF8String:message ?: "SSTP failure"];
    NSUInteger generation = provider.sessionGeneration;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (provider.sessionGeneration != generation) {
            return;
        }
        [provider handleSessionFailureWithCode:errCode stage:errStage message:text generation:generation];
    });
}

#pragma mark - Status persistence / messaging

- (void)persistStatus {
    /* Status is exposed to the app via handleAppMessage / get_status.
     * App Groups are not enabled in current provisioning profiles. */
}

- (void)clearPersistedError {
    self.lastErrorCode = nil;
    self.lastErrorMessage = nil;
}

- (NSDictionary *)statusDictionary {
    NSMutableDictionary *dict = [@{
        @"stage": self.currentStage ?: @(SSTP_IOS_STAGE_IDLE),
        @"connected": @(self.packetLoopRunning),
        @"reconnectAttempt": @(self.reconnectAttempt),
        @"reconnectMax": @(kSSTPMaxReconnectAttempts),
    } mutableCopy];
    if (self.lastErrorCode.length > 0) {
        dict[@"lastError"] = @{
            @"code": self.lastErrorCode,
            @"stage": self.currentStage ?: @(SSTP_IOS_STAGE_ERROR),
            @"message": self.lastErrorMessage ?: @"",
        };
    }
    return dict;
}

- (void)completeStartWithError:(NSError * _Nullable)error {
    if (self.startCompletionCalled) return;
    self.startCompletionCalled = YES;
    if (self.pendingStartHandler) {
        self.pendingStartHandler(error);
        self.pendingStartHandler = nil;
    }
}

#pragma mark - Credentials / TLS config

- (NSString *)passwordFromReference:(NSData *)passwordReference {
    if (passwordReference.length == 0) return @"";
    NSDictionary *query = @{
        (__bridge id)kSecValuePersistentRef: passwordReference,
        (__bridge id)kSecReturnData: @YES,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) {
        return @"";
    }
    NSData *data = (__bridge_transfer NSData *)result;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
}

- (void)loadTLSConfigFromProtocol:(NETunnelProviderProtocol *)proto options:(NSDictionary *)options {
    NSDictionary *providerConfig = proto.providerConfiguration ?: @{};
    NSString *mode = options[SSTPConfigTLSModeKey] ?: providerConfig[SSTPConfigTLSModeKey] ?: @"system";
    if ([mode isEqualToString:@"custom_ca"]) {
        self.tlsMode = SSTP_IOS_TLS_CUSTOM_CA;
    } else if ([mode isEqualToString:@"pinned"]) {
        self.tlsMode = SSTP_IOS_TLS_PINNED;
#if DEBUG
    } else if ([mode isEqualToString:@"insecure_debug"]) {
        self.tlsMode = SSTP_IOS_TLS_INSECURE_DEBUG;
#endif
    } else {
        self.tlsMode = SSTP_IOS_TLS_SYSTEM;
    }
    self.caPem = options[SSTPConfigCAPEMKey] ?: providerConfig[SSTPConfigCAPEMKey];
    self.pinSha256 = options[SSTPConfigPinSHA256Key] ?: providerConfig[SSTPConfigPinSHA256Key];
}

#pragma mark - Start / stop

- (void)startTunnelWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
    NETunnelProviderProtocol *proto = (NETunnelProviderProtocol *)self.protocolConfiguration;
    NSString *server = options[@"server"] ?: proto.serverAddress ?: @"";
    NSString *username = options[@"username"] ?: proto.username ?: @"";
    NSString *password = options[@"password"] ?: @"";

    if (password.length == 0 && proto.passwordReference) {
        password = [self passwordFromReference:proto.passwordReference];
    }

    self.pendingStartHandler = completionHandler;
    self.startCompletionCalled = NO;
    self.userStopRequested = NO;
    self.reconnectAttempt = 0;
    self.reconnectScheduled = NO;
    self.currentStage = @(SSTP_IOS_STAGE_IDLE);
    [self clearPersistedError];
    [self loadTLSConfigFromProtocol:proto options:options ?: @{}];

    if (server.length == 0 || username.length == 0 || password.length == 0) {
        NSError *error = SSTPMakeError(@(SSTP_IOS_ERR_MISSING_CREDENTIALS),
                                       @(SSTP_IOS_STAGE_ERROR),
                                       @"Не заданы сервер, логин или пароль");
        self.lastErrorCode = @(SSTP_IOS_ERR_MISSING_CREDENTIALS);
        self.lastErrorMessage = error.localizedDescription;
        self.currentStage = @(SSTP_IOS_STAGE_ERROR);
        [self persistStatus];
        [self completeStartWithError:error];
        return;
    }

    self.server = server;
    self.username = username;
    self.password = password;

    NSString *caBundle = [[NSBundle mainBundle] pathForResource:@"cacert" ofType:@"pem"];
    if (caBundle.length > 0) {
        setenv("SSTP_CA_BUNDLE", caBundle.fileSystemRepresentation, 1);
    }

    [self beginSessionWithGeneration:++self.sessionGeneration];
}

- (void)beginSessionWithGeneration:(NSUInteger)generation {
    if (self.userStopRequested || self.sessionGeneration != generation) {
        return;
    }

    if (self.session) {
        sstp_ios_session_stop(self.session);
        sstp_ios_session_free(self.session);
        self.session = NULL;
    }

    self.session = sstp_ios_session_create(on_ready, on_packet, on_stage, on_fail, (__bridge void *)self);
    NSString *serverCopy = [self.server copy];
    NSString *userCopy = [self.username copy];
    NSString *passCopy = [self.password copy];
    NSString *caCopy = [self.caPem copy];
    NSString *pinCopy = [self.pinSha256 copy];
    sstp_ios_tls_mode_t tlsMode = self.tlsMode;

    self.workerThread = [[NSThread alloc] initWithBlock:^{
        sstp_ios_start_params_t params;
        memset(&params, 0, sizeof(params));
        params.server = serverCopy.UTF8String;
        params.username = userCopy.UTF8String;
        params.password = passCopy.UTF8String;
        params.tls_mode = tlsMode;
        if (caCopy.length > 0) {
            params.ca_pem = caCopy.UTF8String;
            params.ca_pem_len = strlen(caCopy.UTF8String);
        }
        if (pinCopy.length > 0) {
            params.pin_sha256_hex = pinCopy.UTF8String;
        }

        int rc = sstp_ios_session_start_ex(self.session, &params);
        if (rc != 0) {
            const char *code = sstp_ios_session_last_error_code(self.session) ?: SSTP_IOS_ERR_INTERNAL;
            const char *stage = sstp_ios_session_stage(self.session) ?: SSTP_IOS_STAGE_ERROR;
            const char *msg = sstp_ios_session_last_error_message(self.session) ?: "Не удалось запустить SSTP-сессию";
            on_fail((__bridge void *)self, code, stage, msg);
            return;
        }
        sstp_ios_session_run(self.session);
    }];
    self.workerThread.name = @"sstp-worker";
    [self.workerThread start];
}

- (void)handleSessionFailureWithCode:(NSString *)code
                               stage:(NSString *)stage
                             message:(NSString *)message
                          generation:(NSUInteger)generation {
    if (self.sessionGeneration != generation || self.userStopRequested) {
        return;
    }

    self.lastErrorCode = code;
    self.lastErrorMessage = message;
    self.currentStage = stage.length ? stage : @(SSTP_IOS_STAGE_ERROR);
    [self persistStatus];

    BOOL fatal = sstp_ios_error_is_fatal(code.UTF8String) != 0;
    BOOL canReconnect = !fatal &&
                        self.reconnectAttempt < kSSTPMaxReconnectAttempts &&
                        !self.reconnectScheduled;

    if (canReconnect) {
        self.reconnectAttempt += 1;
        self.reconnectScheduled = YES;
        self.currentStage = @(SSTP_IOS_STAGE_RECONNECTING);
        [self persistStatus];

        NSTimeInterval delays[] = {1.0, 2.0, 5.0};
        NSTimeInterval delay = delays[MIN(self.reconnectAttempt, 3) - 1];
        NSUInteger gen = generation;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            self.reconnectScheduled = NO;
            if (self.userStopRequested || self.sessionGeneration != gen) {
                return;
            }
            // Bump generation so stale callbacks from the old worker are ignored.
            NSUInteger nextGen = ++self.sessionGeneration;
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                [self teardownWorkerKeepingCredentials];
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (self.userStopRequested) return;
                    [self beginSessionWithGeneration:nextGen];
                });
            });
        });
        return;
    }

    NSError *error = SSTPMakeError(code, stage, message);
    [self completeStartWithError:error];
    [self cancelTunnelWithError:error];
}

- (void)teardownWorkerKeepingCredentials {
    self.packetLoopRunning = NO;
    sstp_ios_session_t *session = self.session;
    NSThread *worker = self.workerThread;
    self.session = NULL;
    self.workerThread = nil;
    if (session) {
        sstp_ios_session_stop(session);
    }
    if (worker) {
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kSSTPStopTimeoutSeconds];
        while (!worker.isFinished && [deadline timeIntervalSinceNow] > 0) {
            [NSThread sleepForTimeInterval:0.05];
        }
    }
    if (session) {
        sstp_ios_session_free(session);
    }
}

- (void)applyTunnelSettingsWithLocalIP:(NSString *)local
                               gateway:(NSString *)gateway
                                  dns1:(NSString *)dns1
                                  dns2:(NSString *)dns2
                            generation:(NSUInteger)generation {
    if (self.sessionGeneration != generation || self.userStopRequested) {
        return;
    }

    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:gateway];

    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[local]
                                                         subnetMasks:@[@"255.255.255.255"]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    settings.IPv4Settings = ipv4;
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[dns1, dns2]];
    settings.MTU = @1400;

    __weak typeof(self) weakSelf = self;
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf || strongSelf.sessionGeneration != generation) return;
        if (error) {
            strongSelf.lastErrorCode = @(SSTP_IOS_ERR_INTERNAL);
            strongSelf.lastErrorMessage = error.localizedDescription;
            strongSelf.currentStage = @(SSTP_IOS_STAGE_ERROR);
            [strongSelf persistStatus];
            [strongSelf completeStartWithError:error];
            [strongSelf cancelTunnelWithError:error];
            return;
        }
        strongSelf.currentStage = @(SSTP_IOS_STAGE_CONNECTED);
        [strongSelf clearPersistedError];
        [strongSelf persistStatus];
        [strongSelf completeStartWithError:nil];
        [strongSelf startPacketLoop];
    }];
}

- (void)startPacketLoop {
    if (self.packetLoopRunning) return;
    self.packetLoopRunning = YES;
    [self readPackets];
}

- (void)readPackets {
    if (!self.packetLoopRunning) return;
    __weak typeof(self) weakSelf = self;
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf || !strongSelf.packetLoopRunning || !strongSelf.session) return;

        for (NSUInteger i = 0; i < packets.count; i++) {
            NSData *packet = packets[i];
            NSInteger proto = protocols[i].integerValue;
            if (proto == AF_INET || proto == AF_INET6) {
                sstp_ios_session_write_ip(strongSelf.session,
                                          packet.bytes,
                                          packet.length);
            }
        }
        [strongSelf readPackets];
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    self.userStopRequested = YES;
    self.reconnectScheduled = NO;
    self.packetLoopRunning = NO;
    self.currentStage = @(SSTP_IOS_STAGE_DISCONNECTING);
    if (reason == NEProviderStopReasonUserInitiated) {
        self.lastErrorCode = @(SSTP_IOS_ERR_CANCELLED);
        self.lastErrorMessage = @"Отключено пользователем";
    }
    [self persistStatus];
    self.sessionGeneration += 1;

    sstp_ios_session_t *session = self.session;
    NSThread *worker = self.workerThread;
    self.session = NULL;
    self.workerThread = nil;

    if (session) {
        sstp_ios_session_stop(session);
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (worker) {
            NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kSSTPStopTimeoutSeconds];
            while (!worker.isFinished && [deadline timeIntervalSinceNow] > 0) {
                [NSThread sleepForTimeInterval:0.05];
            }
        }
        if (session) {
            sstp_ios_session_free(session);
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.currentStage = @(SSTP_IOS_STAGE_IDLE);
            [self persistStatus];
            completionHandler();
        });
    });
}

- (void)handleAppMessage:(NSData *)messageData completionHandler:(void (^)(NSData *))completionHandler {
    if (!completionHandler) return;

    NSDictionary *request = nil;
    if (messageData.length > 0) {
        request = [NSJSONSerialization JSONObjectWithData:messageData options:0 error:nil];
    }
    NSString *action = request[SSTPMsgActionKey] ?: SSTPMsgActionGetStatus;
    if (![action isEqualToString:SSTPMsgActionGetStatus]) {
        completionHandler(nil);
        return;
    }

    NSDictionary *payload = [self statusDictionary];
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    completionHandler(data);
}

@end
