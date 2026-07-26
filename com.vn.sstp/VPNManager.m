//
//  VPNManager.m
//  com.vn.sstp
//

#import "VPNManager.h"
#import "KeychainHelper.h"
#import "../shared/SSTPShared.h"

NSNotificationName const VPNManagerStatusDidChangeNotification = @"VPNManagerStatusDidChangeNotification";

static NSString * const kPasswordAccount = @"sstp-vpn-password";
static NSString * const kPrefsServer = @"sstp.server";
static NSString * const kPrefsUsername = @"sstp.username";
static NSString * const kPrefsTLSMode = @"sstp.tlsMode";
static NSString * const kPrefsCAPEM = @"sstp.caPem";
static NSString * const kPrefsPin = @"sstp.pinSha256";

@interface VPNManager ()
@property (nonatomic, strong, nullable) NETunnelProviderManager *manager;
@property (nonatomic, copy) NSString *stage;
@property (nonatomic, copy, nullable) NSString *lastErrorCode;
@property (nonatomic, copy, nullable) NSString *lastErrorMessage;
@property (nonatomic, assign) BOOL connectRequested;
@end

@implementation VPNManager

+ (instancetype)sharedManager {
    static VPNManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[VPNManager alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _stage = @"idle";
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(vpnStatusDidChange:)
                                                     name:NEVPNStatusDidChangeNotification
                                                   object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (NSString *)tunnelBundleIdentifier {
    NSString *appId = [NSBundle mainBundle].bundleIdentifier ?: @"ru.altatec.sstp-client";
    return [appId stringByAppendingString:@".tunnel"];
}

- (NEVPNStatus)status {
    return self.manager.connection.status;
}

- (BOOL)isConnected {
    return self.status == NEVPNStatusConnected;
}

- (BOOL)isConnecting {
    NEVPNStatus status = self.status;
    return status == NEVPNStatusConnecting || status == NEVPNStatusReasserting;
}

- (NSString *)lastErrorHint {
    return SSTPLocalizedHintForCode(self.lastErrorCode);
}

- (NSString *)statusText {
    NEVPNStatus status = self.status;
    switch (status) {
        case NEVPNStatusInvalid:
            return @"Профиль не настроен";
        case NEVPNStatusDisconnected:
            if (self.lastErrorCode.length > 0 && ![self.lastErrorCode isEqualToString:@"cancelled"]) {
                return [NSString stringWithFormat:@"Отключено · %@", SSTPLocalizedHintForCode(self.lastErrorCode)];
            }
            return @"Отключено";
        case NEVPNStatusConnecting:
            return [NSString stringWithFormat:@"Подключение · %@", SSTPLocalizedStage(self.stage)];
        case NEVPNStatusConnected:
            return @"Подключено";
        case NEVPNStatusReasserting:
            return [NSString stringWithFormat:@"Переподключение · %@", SSTPLocalizedStage(self.stage)];
        case NEVPNStatusDisconnecting:
            return @"Отключение…";
    }
    return @"Неизвестно";
}

- (void)notifyStatusChanged {
    [[NSNotificationCenter defaultCenter] postNotificationName:VPNManagerStatusDidChangeNotification object:self];
}

- (void)readPersistedErrorFromAppGroup {
    NSUserDefaults *defaults = SSTPSharedDefaults();
    NSString *code = [defaults stringForKey:SSTPAppGroupLastErrorCodeKey];
    NSString *message = [defaults stringForKey:SSTPAppGroupLastErrorMessageKey];
    NSString *stage = [defaults stringForKey:SSTPAppGroupLastStageKey];
    if (stage.length > 0) {
        self.stage = stage;
    }
    if (code.length > 0) {
        self.lastErrorCode = code;
        self.lastErrorMessage = message;
    }
}

- (void)applyStatusPayload:(NSDictionary *)payload {
    if (![payload isKindOfClass:[NSDictionary class]]) return;
    NSString *stage = payload[@"stage"];
    if ([stage isKindOfClass:[NSString class]] && stage.length > 0) {
        self.stage = stage;
    }
    NSDictionary *lastError = payload[@"lastError"];
    if ([lastError isKindOfClass:[NSDictionary class]]) {
        NSString *code = lastError[@"code"];
        NSString *message = lastError[@"message"];
        if ([code isKindOfClass:[NSString class]] && code.length > 0) {
            self.lastErrorCode = code;
            self.lastErrorMessage = [message isKindOfClass:[NSString class]] ? message : nil;
        }
    } else if ([payload[@"connected"] boolValue]) {
        self.lastErrorCode = nil;
        self.lastErrorMessage = nil;
    }
}

- (void)refreshTunnelStatusWithCompletion:(void (^)(void))completion {
    NETunnelProviderSession *session = (NETunnelProviderSession *)self.manager.connection;
    if (![session isKindOfClass:[NETunnelProviderSession class]] ||
        self.status == NEVPNStatusInvalid ||
        self.status == NEVPNStatusDisconnected) {
        [self readPersistedErrorFromAppGroup];
        if (completion) completion();
        [self notifyStatusChanged];
        return;
    }

    NSDictionary *request = @{SSTPMsgActionKey: SSTPMsgActionGetStatus};
    NSData *data = [NSJSONSerialization dataWithJSONObject:request options:0 error:nil];
    NSError *sendError = nil;
    BOOL sent = [session sendProviderMessage:data
                             returnError:&sendError
                       responseHandler:^(NSData *responseData) {
        if (responseData.length > 0) {
            NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:nil];
            [self applyStatusPayload:payload];
        } else {
            [self readPersistedErrorFromAppGroup];
        }
        if (completion) completion();
        [self notifyStatusChanged];
    }];
    if (!sent) {
        [self readPersistedErrorFromAppGroup];
        if (completion) completion();
        [self notifyStatusChanged];
    }
}

- (void)vpnStatusDidChange:(NSNotification *)notification {
    NEVPNStatus status = self.status;
    if (status == NEVPNStatusConnected) {
        self.connectRequested = NO;
        self.stage = @"connected";
        self.lastErrorCode = nil;
        self.lastErrorMessage = nil;
    } else if (status == NEVPNStatusConnecting || status == NEVPNStatusReasserting) {
        if ([self.stage isEqualToString:@"idle"] || [self.stage isEqualToString:@"connected"] ||
            [self.stage isEqualToString:@"error"]) {
            self.stage = @"resolving";
        }
    } else if (status == NEVPNStatusDisconnecting) {
        self.stage = @"disconnecting";
    } else if (status == NEVPNStatusDisconnected) {
        self.connectRequested = NO;
        [self readPersistedErrorFromAppGroup];
        if (!self.lastErrorCode.length) {
            self.stage = @"idle";
        } else {
            self.stage = @"error";
        }
    }

    [self refreshTunnelStatusWithCompletion:nil];
}

- (void)reloadWithCompletion:(void (^)(NSError * _Nullable))completion {
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        if (error) {
            if (completion) completion(error);
            return;
        }

        NETunnelProviderManager *found = nil;
        for (NETunnelProviderManager *manager in managers) {
            NETunnelProviderProtocol *proto = (NETunnelProviderProtocol *)manager.protocolConfiguration;
            if ([proto isKindOfClass:[NETunnelProviderProtocol class]] &&
                [proto.providerBundleIdentifier isEqualToString:[self tunnelBundleIdentifier]]) {
                found = manager;
                break;
            }
        }

        self.manager = found ?: [[NETunnelProviderManager alloc] init];
        if (completion) completion(nil);
        [self notifyStatusChanged];
    }];
}

- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                         completion:(void (^)(NSError * _Nullable))completion {
    NSString *mode = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsTLSMode] ?: @"system";
    NSString *ca = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsCAPEM];
    NSString *pin = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsPin];
    [self saveConfigurationWithServer:server
                             username:username
                             password:password
                              tlsMode:mode
                                caPem:ca
                            pinSha256:pin
                           completion:completion];
}

- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                            tlsMode:(NSString *)tlsMode
                              caPem:(NSString *)caPem
                          pinSha256:(NSString *)pinSha256
                         completion:(void (^)(NSError * _Nullable))completion {
    NSString *trimmedServer = [server stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *trimmedUser = [username stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

    if (trimmedServer.length == 0 || trimmedUser.length == 0 || password.length == 0) {
        if (completion) {
            completion(SSTPMakeError(@"missing_credentials", @"error", @"Заполните сервер, логин и пароль"));
        }
        return;
    }

    NSError *keychainError = nil;
    if (![KeychainHelper setPassword:password forAccount:kPasswordAccount error:&keychainError]) {
        if (completion) completion(keychainError);
        return;
    }

    NSData *passwordRef = [KeychainHelper passwordReferenceForAccount:kPasswordAccount error:&keychainError];
    if (!passwordRef) {
        if (completion) completion(keychainError ?: SSTPMakeError(@"internal", @"error",
                                                                  @"Не удалось подготовить пароль для VPN-профиля"));
        return;
    }

    NSString *mode = tlsMode.length ? tlsMode : @"system";
    NSMutableDictionary *providerConfiguration = [@{
        @"server": trimmedServer,
        @"username": trimmedUser,
        SSTPConfigTLSModeKey: mode,
    } mutableCopy];
    if (caPem.length > 0) {
        providerConfiguration[SSTPConfigCAPEMKey] = caPem;
    }
    if (pinSha256.length > 0) {
        providerConfiguration[SSTPConfigPinSHA256Key] = pinSha256;
    }

    void (^configureAndSave)(void) = ^{
        NETunnelProviderProtocol *proto = [[NETunnelProviderProtocol alloc] init];
        proto.providerBundleIdentifier = [self tunnelBundleIdentifier];
        proto.serverAddress = trimmedServer;
        proto.username = trimmedUser;
        proto.passwordReference = passwordRef;
        proto.disconnectOnSleep = NO;
        proto.providerConfiguration = providerConfiguration;

        self.manager.protocolConfiguration = proto;
        self.manager.localizedDescription = @"SSTP Client";
        self.manager.enabled = YES;

        [self.manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
            if (saveError) {
                if (completion) completion(saveError);
                return;
            }

            NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
            [defaults setObject:trimmedServer forKey:kPrefsServer];
            [defaults setObject:trimmedUser forKey:kPrefsUsername];
            [defaults setObject:mode forKey:kPrefsTLSMode];
            if (caPem.length > 0) {
                [defaults setObject:caPem forKey:kPrefsCAPEM];
            } else {
                [defaults removeObjectForKey:kPrefsCAPEM];
            }
            if (pinSha256.length > 0) {
                [defaults setObject:pinSha256 forKey:kPrefsPin];
            } else {
                [defaults removeObjectForKey:kPrefsPin];
            }
            [defaults synchronize];

            [self.manager loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                if (completion) completion(loadError);
                [self notifyStatusChanged];
            }];
        }];
    };

    if (!self.manager) {
        [self reloadWithCompletion:^(NSError *error) {
            if (error) {
                if (completion) completion(error);
                return;
            }
            configureAndSave();
        }];
    } else {
        configureAndSave();
    }
}

- (void)connectWithCompletion:(void (^)(NSError * _Nullable))completion {
    if (!self.manager.protocolConfiguration) {
        if (completion) {
            completion(SSTPMakeError(@"missing_credentials", @"error", @"Сначала сохраните настройки VPN"));
        }
        return;
    }

    // Prevent double-start races from UI double-tap.
    if (self.isConnecting || self.isConnected || self.connectRequested) {
        if (completion) completion(nil);
        return;
    }

    NSString *server = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsServer] ?: @"";
    NSString *username = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsUsername] ?: @"";
    NSString *password = [KeychainHelper passwordForAccount:kPasswordAccount error:nil] ?: @"";
    NSString *tlsMode = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsTLSMode] ?: @"system";
    NSString *caPem = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsCAPEM];
    NSString *pin = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsPin];

    self.connectRequested = YES;
    self.lastErrorCode = nil;
    self.lastErrorMessage = nil;
    self.stage = @"resolving";
    NSUserDefaults *shared = SSTPSharedDefaults();
    [shared removeObjectForKey:SSTPAppGroupLastErrorCodeKey];
    [shared removeObjectForKey:SSTPAppGroupLastErrorStageKey];
    [shared removeObjectForKey:SSTPAppGroupLastErrorMessageKey];
    [shared synchronize];

    NSMutableDictionary *options = [@{
        @"server": server,
        @"username": username,
        @"password": password,
        SSTPConfigTLSModeKey: tlsMode,
    } mutableCopy];
    if (caPem.length > 0) options[SSTPConfigCAPEMKey] = caPem;
    if (pin.length > 0) options[SSTPConfigPinSHA256Key] = pin;

    NSError *startError = nil;
    BOOL started = [self.manager.connection startVPNTunnelWithOptions:options
                                                       andReturnError:&startError];

    if (!started) {
        self.connectRequested = NO;
        self.stage = @"error";
        self.lastErrorCode = @"internal";
        self.lastErrorMessage = startError.localizedDescription;
        if (completion) completion(startError);
        [self notifyStatusChanged];
        return;
    }
    if (completion) completion(nil);
    [self notifyStatusChanged];
}

- (void)disconnect {
    self.connectRequested = NO;
    self.stage = @"disconnecting";
    [self.manager.connection stopVPNTunnel];
    [self notifyStatusChanged];
}

@end
