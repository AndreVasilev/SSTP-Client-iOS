//
//  SSTPShared.h
//  Shared constants between app and Packet Tunnel extension.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

static inline NSString *SSTPAppGroupIdentifier(void) {
    NSString *bundleId = [NSBundle mainBundle].bundleIdentifier ?: @"cen.com-vn-sstp";
    if ([bundleId hasSuffix:@".tunnel"]) {
        bundleId = [bundleId substringToIndex:bundleId.length - @".tunnel".length];
    }
    return [@"group." stringByAppendingString:bundleId];
}

static NSString * const SSTPErrorDomain = @"ru.altatec.sstp";

static NSString * const SSTPUserInfoCodeKey = @"code";
static NSString * const SSTPUserInfoStageKey = @"stage";

static NSString * const SSTPAppGroupLastErrorCodeKey = @"lastErrorCode";
static NSString * const SSTPAppGroupLastErrorStageKey = @"lastErrorStage";
static NSString * const SSTPAppGroupLastErrorMessageKey = @"lastErrorMessage";
static NSString * const SSTPAppGroupLastStageKey = @"lastStage";
static NSString * const SSTPAppGroupConnectedKey = @"connected";

static NSString * const SSTPMsgActionKey = @"action";
static NSString * const SSTPMsgActionGetStatus = @"get_status";

static NSString * const SSTPConfigTLSModeKey = @"tlsMode";
static NSString * const SSTPConfigCAPEMKey = @"caPem";
static NSString * const SSTPConfigPinSHA256Key = @"pinSha256";
static NSString * const SSTPConfigServerHostKey = @"serverHost";
static NSString * const SSTPConfigServerPortKey = @"serverPort";

static NSString * const SSTPAppGroupTunnelStartedKey = @"tunnelStarted";

/** Split "host", "host:port", "https://host:port/path" into host + port (default 443). */
static inline BOOL SSTPParseServerEndpoint(NSString * _Nullable server,
                                           NSString * _Nullable * _Nullable hostOut,
                                           NSString * _Nullable * _Nullable portOut) {
    NSString *trimmed = [[server ?: @"" stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] copy];
    if (trimmed.length == 0) {
        return NO;
    }

    NSRange schemeRange = [trimmed rangeOfString:@"://"];
    if (schemeRange.location != NSNotFound) {
        trimmed = [trimmed substringFromIndex:schemeRange.location + schemeRange.length];
    }

    NSRange pathRange = [trimmed rangeOfString:@"/"];
    if (pathRange.location != NSNotFound) {
        trimmed = [trimmed substringToIndex:pathRange.location];
    }

    if ([trimmed hasPrefix:@"["]) {
        NSRange closeBracket = [trimmed rangeOfString:@"]"];
        if (closeBracket.location != NSNotFound) {
            NSString *host = [trimmed substringWithRange:NSMakeRange(1, closeBracket.location - 1)];
            NSString *rest = (closeBracket.location + 1 < trimmed.length)
                ? [trimmed substringFromIndex:closeBracket.location + 1]
                : @"";
            if ([rest hasPrefix:@":"]) {
                rest = [rest substringFromIndex:1];
            }
            if (hostOut) {
                *hostOut = host;
            }
            if (portOut) {
                *portOut = rest.length > 0 ? rest : @"443";
            }
            return host.length > 0;
        }
    }

    NSRange colon = [trimmed rangeOfString:@":" options:NSBackwardsSearch];
    if (colon.location != NSNotFound) {
        NSString *host = [trimmed substringToIndex:colon.location];
        NSString *port = [trimmed substringFromIndex:colon.location + 1];
        if (hostOut) {
            *hostOut = host;
        }
        if (portOut) {
            *portOut = port.length > 0 ? port : @"443";
        }
        return host.length > 0;
    }

    if (hostOut) {
        *hostOut = trimmed;
    }
    if (portOut) {
        *portOut = @"443";
    }
    return YES;
}

typedef NS_ENUM(NSInteger, SSTPErrorNumericCode) {
    SSTPErrorNumericMissingCredentials = 1,
    SSTPErrorNumericRuntime = 2,
    SSTPErrorNumericCancelled = 3,
    SSTPErrorNumericInternal = 99,
};

static inline NSUserDefaults * _Nullable SSTPSharedDefaults(void) {
    return [[NSUserDefaults alloc] initWithSuiteName:SSTPAppGroupIdentifier()];
}

static inline NSError *SSTPMakeError(NSString *code, NSString *stage, NSString *message) {
    NSInteger numeric = SSTPErrorNumericRuntime;
    if ([code isEqualToString:@"missing_credentials"]) {
        numeric = SSTPErrorNumericMissingCredentials;
    } else if ([code isEqualToString:@"cancelled"]) {
        numeric = SSTPErrorNumericCancelled;
    } else if ([code isEqualToString:@"internal"]) {
        numeric = SSTPErrorNumericInternal;
    }
    return [NSError errorWithDomain:SSTPErrorDomain
                               code:numeric
                           userInfo:@{
                               NSLocalizedDescriptionKey: message ?: @"SSTP failure",
                               SSTPUserInfoCodeKey: code ?: @"internal",
                               SSTPUserInfoStageKey: stage ?: @"error",
                           }];
}

static inline NSString *SSTPLocalizedHintForCode(NSString * _Nullable code) {
    if ([code isEqualToString:@"dns_resolve"]) {
        return @"Не удалось найти сервер. Проверьте имя хоста и сеть.";
    }
    if ([code isEqualToString:@"tcp_timeout"]) {
        return @"Сервер не ответил вовремя. Проверьте доступность порта 443.";
    }
    if ([code isEqualToString:@"tls_handshake"]) {
        return @"Не удалось установить TLS с сервером.";
    }
    if ([code isEqualToString:@"tls_cert"]) {
        return @"Сертификат сервера не доверен или не совпадает с именем. Добавьте CA/pin или исправьте сервер.";
    }
    if ([code isEqualToString:@"http_upgrade"]) {
        return @"HTTP upgrade SSTP не выполнен. Проверьте, что это SSTP-сервер.";
    }
    if ([code isEqualToString:@"sstp_control"]) {
        return @"Ошибка управляющего канала SSTP.";
    }
    if ([code isEqualToString:@"auth_rejected"]) {
        return @"Сервер отклонил логин или пароль.";
    }
    if ([code isEqualToString:@"ipcp_failed"]) {
        return @"Не удалось получить IP-адрес в туннеле.";
    }
    if ([code isEqualToString:@"crypto_binding"]) {
        return @"Проверка crypto binding SSTP не прошла.";
    }
    if ([code isEqualToString:@"mppe_failed"]) {
        return @"Не удалось согласовать шифрование MPPE.";
    }
    if ([code isEqualToString:@"network_lost"]) {
        return @"Соединение с VPN разорвано. Можно попробовать снова.";
    }
    if ([code isEqualToString:@"missing_credentials"]) {
        return @"Не заданы сервер, логин или пароль.";
    }
    if ([code isEqualToString:@"cancelled"]) {
        return @"Подключение отменено.";
    }
    return @"Не удалось подключить VPN.";
}

static inline NSString *SSTPLocalizedStage(NSString * _Nullable stage) {
    if ([stage isEqualToString:@"resolving"]) return @"DNS…";
    if ([stage isEqualToString:@"tcp_tls"]) return @"TLS…";
    if ([stage isEqualToString:@"http_upgrade"]) return @"HTTP SSTP…";
    if ([stage isEqualToString:@"sstp_control"]) return @"SSTP…";
    if ([stage isEqualToString:@"ppp_lcp"]) return @"PPP LCP…";
    if ([stage isEqualToString:@"ppp_auth"]) return @"Аутентификация…";
    if ([stage isEqualToString:@"ppp_ipcp"]) return @"Получение IP…";
    if ([stage isEqualToString:@"ppp_mppe"]) return @"MPPE…";
    if ([stage isEqualToString:@"applying_settings"]) return @"Настройка туннеля…";
    if ([stage isEqualToString:@"connected"]) return @"Подключено";
    if ([stage isEqualToString:@"disconnecting"]) return @"Отключение…";
    if ([stage isEqualToString:@"reconnecting"]) return @"Переподключение…";
    if ([stage isEqualToString:@"error"]) return @"Ошибка";
    return @"Подключение…";
}

NS_ASSUME_NONNULL_END
