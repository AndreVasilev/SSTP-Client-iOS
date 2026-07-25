//
//  VPNManager.m
//  com.vn.sstp
//

#import "VPNManager.h"
#import "KeychainHelper.h"

NSNotificationName const VPNManagerStatusDidChangeNotification = @"VPNManagerStatusDidChangeNotification";

static NSString * const kPasswordAccount = @"sstp-vpn-password";
static NSString * const kPrefsServer = @"sstp.server";
static NSString * const kPrefsUsername = @"sstp.username";

@interface VPNManager ()
@property (nonatomic, strong, nullable) NETunnelProviderManager *manager;
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

- (NSString *)statusText {
    switch (self.status) {
        case NEVPNStatusInvalid: return @"Профиль не настроен";
        case NEVPNStatusDisconnected: return @"Отключено";
        case NEVPNStatusConnecting: return @"Подключение…";
        case NEVPNStatusConnected: return @"Подключено";
        case NEVPNStatusReasserting: return @"Переподключение…";
        case NEVPNStatusDisconnecting: return @"Отключение…";
    }
    return @"Неизвестно";
}

- (void)vpnStatusDidChange:(NSNotification *)notification {
    [[NSNotificationCenter defaultCenter] postNotificationName:VPNManagerStatusDidChangeNotification object:self];
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
        [[NSNotificationCenter defaultCenter] postNotificationName:VPNManagerStatusDidChangeNotification object:self];
    }];
}

- (void)saveConfigurationWithServer:(NSString *)server
                           username:(NSString *)username
                           password:(NSString *)password
                         completion:(void (^)(NSError * _Nullable))completion {
    NSString *trimmedServer = [server stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *trimmedUser = [username stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

    if (trimmedServer.length == 0 || trimmedUser.length == 0 || password.length == 0) {
        if (completion) {
            completion([NSError errorWithDomain:@"ru.altatec.sstp" code:100 userInfo:@{
                NSLocalizedDescriptionKey: @"Заполните сервер, логин и пароль"
            }]);
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
        if (completion) completion(keychainError ?: [NSError errorWithDomain:@"ru.altatec.sstp" code:101 userInfo:@{
            NSLocalizedDescriptionKey: @"Не удалось подготовить пароль для VPN-профиля"
        }]);
        return;
    }

    void (^configureAndSave)(void) = ^{
        NETunnelProviderProtocol *proto = [[NETunnelProviderProtocol alloc] init];
        proto.providerBundleIdentifier = [self tunnelBundleIdentifier];
        proto.serverAddress = trimmedServer;
        proto.username = trimmedUser;
        proto.passwordReference = passwordRef;
        proto.disconnectOnSleep = NO;
        proto.providerConfiguration = @{
            @"server": trimmedServer,
            @"username": trimmedUser
        };

        self.manager.protocolConfiguration = proto;
        self.manager.localizedDescription = @"SSTP Client";
        self.manager.enabled = YES;

        [self.manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
            if (saveError) {
                if (completion) completion(saveError);
                return;
            }

            [[NSUserDefaults standardUserDefaults] setObject:trimmedServer forKey:kPrefsServer];
            [[NSUserDefaults standardUserDefaults] setObject:trimmedUser forKey:kPrefsUsername];
            [[NSUserDefaults standardUserDefaults] synchronize];

            // iOS requires reload after first save before startTunnel works reliably.
            [self.manager loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                if (completion) completion(loadError);
                [[NSNotificationCenter defaultCenter] postNotificationName:VPNManagerStatusDidChangeNotification object:self];
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
            completion([NSError errorWithDomain:@"ru.altatec.sstp" code:102 userInfo:@{
                NSLocalizedDescriptionKey: @"Сначала сохраните настройки VPN"
            }]);
        }
        return;
    }

    NSString *server = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsServer] ?: @"";
    NSString *username = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefsUsername] ?: @"";
    NSString *password = [KeychainHelper passwordForAccount:kPasswordAccount error:nil] ?: @"";

    NSError *startError = nil;
    BOOL started = [self.manager.connection startVPNTunnelWithOptions:@{
        @"server": server,
        @"username": username,
        @"password": password
    } andReturnError:&startError];

    if (!started) {
        if (completion) completion(startError);
        return;
    }
    if (completion) completion(nil);
}

- (void)disconnect {
    [self.manager.connection stopVPNTunnel];
}

@end
