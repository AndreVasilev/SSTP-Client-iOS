//
//  PacketTunnelProvider.m
//  tunnel
//

#import "PacketTunnelProvider.h"
#import "sstp-ios.h"

@interface PacketTunnelProvider ()
@property (nonatomic, assign) sstp_ios_session_t *session;
@property (nonatomic, strong) NSThread *workerThread;
@property (nonatomic, copy) void (^pendingStartHandler)(NSError * _Nullable);
@property (nonatomic, assign) BOOL packetLoopRunning;
@end

@implementation PacketTunnelProvider

static void on_ready(void *ctx, const char *local_ip, const char *gateway_ip,
                     const char *dns1, const char *dns2)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    NSString *local = [NSString stringWithUTF8String:local_ip ?: "10.0.0.2"];
    NSString *gateway = [NSString stringWithUTF8String:gateway_ip ?: "10.0.0.1"];
    NSString *d1 = [NSString stringWithUTF8String:dns1 ?: "8.8.8.8"];
    NSString *d2 = [NSString stringWithUTF8String:dns2 ?: "8.8.4.4"];

    dispatch_async(dispatch_get_main_queue(), ^{
        [provider applyTunnelSettingsWithLocalIP:local gateway:gateway dns1:d1 dns2:d2];
    });
}

static void on_packet(void *ctx, const uint8_t *ip_packet, size_t len)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    if (!ip_packet || len == 0) return;
    NSData *data = [NSData dataWithBytes:ip_packet length:len];
    dispatch_async(dispatch_get_main_queue(), ^{
        [provider.packetFlow writePackets:@[data] withProtocols:@[@(AF_INET)]];
    });
}

static void on_fail(void *ctx, const char *message)
{
    PacketTunnelProvider *provider = (__bridge PacketTunnelProvider *)ctx;
    NSString *text = [NSString stringWithUTF8String:message ?: "SSTP failure"];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (provider.pendingStartHandler) {
            NSError *error = [NSError errorWithDomain:@"ru.altatec.sstp"
                                                 code:2
                                             userInfo:@{NSLocalizedDescriptionKey: text}];
            provider.pendingStartHandler(error);
            provider.pendingStartHandler = nil;
        }
        [provider cancelTunnelWithError:[NSError errorWithDomain:@"ru.altatec.sstp"
                                                            code:2
                                                        userInfo:@{NSLocalizedDescriptionKey: text}]];
    });
}

- (void)startTunnelWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
    NETunnelProviderProtocol *proto = (NETunnelProviderProtocol *)self.protocolConfiguration;
    NSString *server = options[@"server"] ?: proto.serverAddress ?: @"";
    NSString *username = options[@"username"] ?: proto.username ?: @"";
    NSString *password = options[@"password"] ?: @"";

    if (password.length == 0 && proto.passwordReference) {
        // Best-effort: password should be provided via start options from the app.
        password = @"";
    }

    if (server.length == 0 || username.length == 0 || password.length == 0) {
        completionHandler([NSError errorWithDomain:@"ru.altatec.sstp" code:1 userInfo:@{
            NSLocalizedDescriptionKey: @"Не заданы сервер, логин или пароль"
        }]);
        return;
    }

    self.pendingStartHandler = completionHandler;
    self.session = sstp_ios_session_create(on_ready, on_packet, on_fail, (__bridge void *)self);

    NSString *serverCopy = [server copy];
    NSString *userCopy = [username copy];
    NSString *passCopy = [password copy];

    self.workerThread = [[NSThread alloc] initWithBlock:^{
        int rc = sstp_ios_session_start(self.session,
                                        serverCopy.UTF8String,
                                        userCopy.UTF8String,
                                        passCopy.UTF8String);
        if (rc != 0) {
            on_fail((__bridge void *)self, "Не удалось запустить SSTP-сессию");
            return;
        }
        sstp_ios_session_run(self.session);
    }];
    self.workerThread.name = @"sstp-worker";
    [self.workerThread start];
}

- (void)applyTunnelSettingsWithLocalIP:(NSString *)local
                               gateway:(NSString *)gateway
                                  dns1:(NSString *)dns1
                                  dns2:(NSString *)dns2 {
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:gateway];

    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[local]
                                                         subnetMasks:@[@"255.255.255.255"]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    /* Xcode 26 / iOS 26 SDK: acronym properties are capitalized (IPv4/DNS/MTU). */
    settings.IPv4Settings = ipv4;
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[dns1, dns2]];
    settings.MTU = @1400;

    __weak typeof(self) weakSelf = self;
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        if (strongSelf.pendingStartHandler) {
            strongSelf.pendingStartHandler(error);
            strongSelf.pendingStartHandler = nil;
        }
        if (!error) {
            [strongSelf startPacketLoop];
        }
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
        if (!strongSelf || !strongSelf.packetLoopRunning) return;

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
    self.packetLoopRunning = NO;
    sstp_ios_session_t *session = self.session;
    NSThread *worker = self.workerThread;
    self.session = NULL;
    self.workerThread = nil;

    if (session) {
        sstp_ios_session_stop(session);
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (worker) {
            while (!worker.isFinished) {
                [NSThread sleepForTimeInterval:0.05];
            }
        }
        if (session) {
            sstp_ios_session_free(session);
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completionHandler();
        });
    });
}

- (void)handleAppMessage:(NSData *)messageData completionHandler:(void (^)(NSData *))completionHandler {
    if (completionHandler) completionHandler(nil);
}

@end
