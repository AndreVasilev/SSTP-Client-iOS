//
//  PacketTunnelProvider.m
//  tunnel
//

#import "PacketTunnelProvider.h"

@implementation PacketTunnelProvider

- (void)startTunnelWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
    NSString *server = options[@"server"] ?: ((NETunnelProviderProtocol *)self.protocolConfiguration).serverAddress;
    NSString *username = options[@"username"] ?: ((NETunnelProviderProtocol *)self.protocolConfiguration).username;

    NSLog(@"[SSTP] startTunnel server=%@ user=%@", server, username);

    // The vendored sstp-client is a Linux/pppd CLI stack and is not yet adapted
    // to NEPacketTunnelProvider packetFlow. Fail clearly instead of hanging.
    NSError *error = [NSError errorWithDomain:@"NETunnelProviderErrorDomain"
                                         code:1
                                     userInfo:@{
        NSLocalizedDescriptionKey:
            @"SSTP-движок пока не подключён к Network Extension. "
            @"Профиль и UI готовы, но установка туннеля ещё не реализована.",
        NSLocalizedFailureReasonErrorKey:
            @"Библиотека sstp-client ожидает pppd и не работает как iOS Packet Tunnel.",
        NSLocalizedRecoverySuggestionErrorKey:
            @"Нужна портивная реализация SSTP/PPP поверх NEPacketTunnelFlow."
    }];
    completionHandler(error);
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    completionHandler();
}

- (void)handleAppMessage:(NSData *)messageData completionHandler:(void (^)(NSData *))completionHandler {
    if (completionHandler) {
        completionHandler(nil);
    }
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    completionHandler();
}

- (void)wake {
}

@end
