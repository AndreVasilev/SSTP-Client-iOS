//
//  ViewController.m
//  com.vn.sstp
//

#import "ViewController.h"
#import "VPNManager.h"
#import "KeychainHelper.h"
#import "../shared/SSTPShared.h"

static NSString * const kPrefsServer = @"sstp.server";
static NSString * const kPrefsUsername = @"sstp.username";
static NSString * const kPasswordAccount = @"sstp-vpn-password";
static NSString * const kPrefsTLSMode = @"sstp.tlsMode";
static NSString * const kPrefsCAPEM = @"sstp.caPem";
static NSString * const kPrefsPin = @"sstp.pinSha256";

@interface ViewController () <UITextFieldDelegate, UITextViewDelegate>
@property (nonatomic, strong) CAGradientLayer *backgroundGradient;
@property (nonatomic, strong) UILabel *brandLabel;
@property (nonatomic, strong) UILabel *subtitleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextField *serverField;
@property (nonatomic, strong) UITextField *usernameField;
@property (nonatomic, strong) UITextField *passwordField;
@property (nonatomic, strong) UISegmentedControl *tlsModeControl;
@property (nonatomic, strong) UITextView *caPemView;
@property (nonatomic, strong) UITextField *pinField;
@property (nonatomic, strong) UIStackView *advancedStack;
@property (nonatomic, strong) UIButton *connectButton;
@property (nonatomic, strong) UILabel *hintLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self buildBackground];
    [self buildUI];
    [self loadSavedFields];
    [self refreshTLSFieldsVisibility];
    [self refreshStatus];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refreshStatus)
                                                 name:VPNManagerStatusDidChangeNotification
                                               object:nil];

    [[VPNManager sharedManager] reloadWithCompletion:^(NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self refreshStatus];
            if (error) {
                self.hintLabel.text = error.localizedDescription;
            }
        });
    }];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.backgroundGradient.frame = self.view.bounds;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

#pragma mark - UI

- (void)buildBackground {
    self.backgroundGradient = [CAGradientLayer layer];
    self.backgroundGradient.colors = @[
        (id)[UIColor colorWithRed:0.07 green:0.16 blue:0.22 alpha:1].CGColor,
        (id)[UIColor colorWithRed:0.10 green:0.28 blue:0.32 alpha:1].CGColor,
        (id)[UIColor colorWithRed:0.16 green:0.38 blue:0.36 alpha:1].CGColor
    ];
    self.backgroundGradient.startPoint = CGPointMake(0.1, 0.0);
    self.backgroundGradient.endPoint = CGPointMake(0.9, 1.0);
    [self.view.layer insertSublayer:self.backgroundGradient atIndex:0];
}

- (UILabel *)makeLabel:(NSString *)text font:(UIFont *)font color:(UIColor *)color {
    UILabel *label = [[UILabel alloc] init];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.text = text;
    label.font = font;
    label.textColor = color;
    label.numberOfLines = 0;
    return label;
}

- (UITextField *)makeField:(NSString *)placeholder secure:(BOOL)secure {
    UITextField *field = [[UITextField alloc] init];
    field.translatesAutoresizingMaskIntoConstraints = NO;
    field.placeholder = placeholder;
    field.secureTextEntry = secure;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.spellCheckingType = UITextSpellCheckingTypeNo;
    field.textContentType = secure ? UITextContentTypePassword : UITextContentTypeUsername;
    field.keyboardType = secure ? UIKeyboardTypeDefault : UIKeyboardTypeASCIICapable;
    field.borderStyle = UITextBorderStyleNone;
    field.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.10];
    field.textColor = UIColor.whiteColor;
    field.attributedPlaceholder = [[NSAttributedString alloc] initWithString:placeholder attributes:@{
        NSForegroundColorAttributeName: [[UIColor whiteColor] colorWithAlphaComponent:0.45]
    }];
    field.layer.cornerRadius = 14;
    field.clipsToBounds = YES;
    field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 16, 1)];
    field.leftViewMode = UITextFieldViewModeAlways;
    field.rightView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 16, 1)];
    field.rightViewMode = UITextFieldViewModeAlways;
    field.delegate = self;
    field.returnKeyType = secure ? UIReturnKeyGo : UIReturnKeyNext;
    return field;
}

- (void)buildUI {
    UIFont *brandFont = [UIFont fontWithName:@"AvenirNext-Heavy" size:34] ?: [UIFont boldSystemFontOfSize:34];
    UIFont *bodyFont = [UIFont fontWithName:@"AvenirNext-Regular" size:15] ?: [UIFont systemFontOfSize:15];
    UIFont *statusFont = [UIFont fontWithName:@"AvenirNext-DemiBold" size:16] ?: [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];

    self.brandLabel = [self makeLabel:@"SSTP Client" font:brandFont color:UIColor.whiteColor];
    self.subtitleLabel = [self makeLabel:@"Подключение к серверу Microsoft SSTP"
                                    font:bodyFont
                                   color:[[UIColor whiteColor] colorWithAlphaComponent:0.72]];
    self.statusLabel = [self makeLabel:@"Отключено" font:statusFont color:[UIColor colorWithRed:0.72 green:0.92 blue:0.86 alpha:1]];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;

    self.serverField = [self makeField:@"Сервер (vpn.example.com)" secure:NO];
    self.serverField.keyboardType = UIKeyboardTypeURL;
    self.serverField.textContentType = UITextContentTypeURL;
    self.usernameField = [self makeField:@"Имя пользователя" secure:NO];
    self.passwordField = [self makeField:@"Пароль" secure:YES];

    self.tlsModeControl = [[UISegmentedControl alloc] initWithItems:@[@"System", @"CA", @"Pin"]];
    self.tlsModeControl.translatesAutoresizingMaskIntoConstraints = NO;
    self.tlsModeControl.selectedSegmentIndex = 0;
    [self.tlsModeControl addTarget:self action:@selector(tlsModeChanged) forControlEvents:UIControlEventValueChanged];
    if (@available(iOS 13.0, *)) {
        self.tlsModeControl.selectedSegmentTintColor = [UIColor colorWithRed:0.86 green:0.95 blue:0.92 alpha:1];
    }

    self.caPemView = [[UITextView alloc] init];
    self.caPemView.translatesAutoresizingMaskIntoConstraints = NO;
    self.caPemView.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.10];
    self.caPemView.textColor = UIColor.whiteColor;
    self.caPemView.font = [UIFont fontWithName:@"Menlo-Regular" size:12] ?: [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.caPemView.layer.cornerRadius = 14;
    self.caPemView.clipsToBounds = YES;
    self.caPemView.delegate = self;
    self.caPemView.textContainerInset = UIEdgeInsetsMake(10, 10, 10, 10);
    self.caPemView.accessibilityLabel = @"Custom CA PEM";

    self.pinField = [self makeField:@"SHA-256 pin (64 hex)" secure:NO];
    self.pinField.autocapitalizationType = UITextAutocapitalizationTypeNone;

    UILabel *advancedTitle = [self makeLabel:@"Доверие TLS"
                                        font:[UIFont fontWithName:@"AvenirNext-DemiBold" size:13] ?: [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold]
                                       color:[[UIColor whiteColor] colorWithAlphaComponent:0.65]];

    self.advancedStack = [[UIStackView alloc] initWithArrangedSubviews:@[
        advancedTitle, self.tlsModeControl, self.caPemView, self.pinField
    ]];
    self.advancedStack.translatesAutoresizingMaskIntoConstraints = NO;
    self.advancedStack.axis = UILayoutConstraintAxisVertical;
    self.advancedStack.spacing = 10;

    self.connectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.connectButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.connectButton.backgroundColor = [UIColor colorWithRed:0.86 green:0.95 blue:0.92 alpha:1];
    [self.connectButton setTitleColor:[UIColor colorWithRed:0.07 green:0.18 blue:0.20 alpha:1] forState:UIControlStateNormal];
    self.connectButton.titleLabel.font = [UIFont fontWithName:@"AvenirNext-DemiBold" size:18] ?: [UIFont boldSystemFontOfSize:18];
    self.connectButton.layer.cornerRadius = 16;
    [self.connectButton addTarget:self action:@selector(connectTapped) forControlEvents:UIControlEventTouchUpInside];

    self.hintLabel = [self makeLabel:@"Введите сервер, логин и пароль, затем нажмите «Подключить»."
                               font:[UIFont fontWithName:@"AvenirNext-Regular" size:13] ?: [UIFont systemFontOfSize:13]
                              color:[[UIColor whiteColor] colorWithAlphaComponent:0.55]];
    self.hintLabel.textAlignment = NSTextAlignmentCenter;

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.spinner.color = UIColor.whiteColor;
    self.spinner.hidesWhenStopped = YES;

    UIStackView *fields = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.serverField, self.usernameField, self.passwordField, self.advancedStack
    ]];
    fields.translatesAutoresizingMaskIntoConstraints = NO;
    fields.axis = UILayoutConstraintAxisVertical;
    fields.spacing = 12;

    UIScrollView *scroll = [[UIScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.brandLabel,
        self.subtitleLabel,
        self.statusLabel,
        fields,
        self.connectButton,
        self.hintLabel
    ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 18;
    [stack setCustomSpacing:8 afterView:self.brandLabel];
    [stack setCustomSpacing:28 afterView:self.subtitleLabel];
    [stack setCustomSpacing:24 afterView:self.statusLabel];
    [stack setCustomSpacing:20 afterView:fields];

    [self.view addSubview:scroll];
    [scroll addSubview:stack];
    [self.view addSubview:self.spinner];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor],
        [scroll.topAnchor constraintEqualToAnchor:guide.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-24],
        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:24],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-24],
        [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-48],
        [self.serverField.heightAnchor constraintEqualToConstant:52],
        [self.usernameField.heightAnchor constraintEqualToConstant:52],
        [self.passwordField.heightAnchor constraintEqualToConstant:52],
        [self.pinField.heightAnchor constraintEqualToConstant:52],
        [self.caPemView.heightAnchor constraintEqualToConstant:110],
        [self.connectButton.heightAnchor constraintEqualToConstant:56],
        [self.spinner.centerXAnchor constraintEqualToAnchor:self.connectButton.centerXAnchor],
        [self.spinner.centerYAnchor constraintEqualToAnchor:self.connectButton.centerYAnchor],
    ]];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(endEditing)];
    [self.view addGestureRecognizer:tap];
}

- (NSString *)selectedTLSMode {
    switch (self.tlsModeControl.selectedSegmentIndex) {
        case 1: return @"custom_ca";
        case 2: return @"pinned";
        default: return @"system";
    }
}

- (void)tlsModeChanged {
    [self refreshTLSFieldsVisibility];
}

- (void)refreshTLSFieldsVisibility {
    NSString *mode = [self selectedTLSMode];
    self.caPemView.hidden = ![mode isEqualToString:@"custom_ca"];
    self.pinField.hidden = ![mode isEqualToString:@"pinned"];
}

- (void)loadSavedFields {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    self.serverField.text = [defaults stringForKey:kPrefsServer];
    self.usernameField.text = [defaults stringForKey:kPrefsUsername];
    self.passwordField.text = [KeychainHelper passwordForAccount:kPasswordAccount error:nil];
    self.caPemView.text = [defaults stringForKey:kPrefsCAPEM] ?: @"";
    self.pinField.text = [defaults stringForKey:kPrefsPin] ?: @"";

    NSString *mode = [defaults stringForKey:kPrefsTLSMode] ?: @"system";
    if ([mode isEqualToString:@"custom_ca"]) {
        self.tlsModeControl.selectedSegmentIndex = 1;
    } else if ([mode isEqualToString:@"pinned"]) {
        self.tlsModeControl.selectedSegmentIndex = 2;
    } else {
        self.tlsModeControl.selectedSegmentIndex = 0;
    }
}

- (void)endEditing {
    [self.view endEditing:YES];
}

#pragma mark - Actions

- (void)connectTapped {
    [self endEditing];

    VPNManager *vpn = [VPNManager sharedManager];
    if (vpn.isConnected || vpn.isConnecting) {
        [vpn disconnect];
        [self refreshStatus];
        return;
    }

    self.connectButton.enabled = NO;
    [self.spinner startAnimating];
    self.hintLabel.text = @"Сохраняем VPN-профиль…";

    NSString *tlsMode = [self selectedTLSMode];
    NSString *caPem = self.caPemView.text;
    NSString *pin = [[self.pinField.text ?: @"" stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] lowercaseString];

    if ([tlsMode isEqualToString:@"custom_ca"] && caPem.length < 32) {
        [self.spinner stopAnimating];
        self.connectButton.enabled = YES;
        self.hintLabel.text = @"Для режима CA вставьте PEM сертификата удостоверяющего центра.";
        return;
    }
    if ([tlsMode isEqualToString:@"pinned"] && pin.length != 64) {
        [self.spinner stopAnimating];
        self.connectButton.enabled = YES;
        self.hintLabel.text = @"Для режима Pin укажите SHA-256 отпечаток листа (64 hex-символа).";
        return;
    }

    [[VPNManager sharedManager] saveConfigurationWithServer:self.serverField.text
                                                   username:self.usernameField.text
                                                   password:self.passwordField.text
                                                    tlsMode:tlsMode
                                                      caPem:caPem
                                                  pinSha256:pin
                                                 completion:^(NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                [self.spinner stopAnimating];
                self.connectButton.enabled = YES;
                self.hintLabel.text = error.localizedDescription;
                [self refreshStatus];
                return;
            }

            self.hintLabel.text = @"Запускаем туннель…";
            [[VPNManager sharedManager] connectWithCompletion:^(NSError *connectError) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.spinner stopAnimating];
                    self.connectButton.enabled = YES;
                    if (connectError) {
                        self.hintLabel.text = connectError.localizedDescription;
                    } else {
                        self.hintLabel.text = @"Ожидаем установку SSTP-сессии…";
                    }
                    [self refreshStatus];
                });
            }];
        });
    }];
}

- (void)refreshStatus {
    VPNManager *vpn = [VPNManager sharedManager];
    self.statusLabel.text = vpn.statusText;

    BOOL busy = vpn.isConnecting || vpn.status == NEVPNStatusDisconnecting;
    if (busy) {
        [self.spinner startAnimating];
    } else {
        [self.spinner stopAnimating];
    }

    NSString *title = (vpn.isConnected || vpn.isConnecting) ? @"Отключить" : @"Подключить";
    [self.connectButton setTitle:title forState:UIControlStateNormal];
    self.connectButton.enabled = !busy || vpn.isConnecting;

    if (vpn.isConnected) {
        self.hintLabel.text = @"VPN активен. Трафик идёт через SSTP-профиль.";
    } else if (vpn.status == NEVPNStatusDisconnected && vpn.lastErrorCode.length > 0 &&
               ![vpn.lastErrorCode isEqualToString:@"cancelled"]) {
        NSString *hint = vpn.lastErrorHint ?: @"Не удалось подключить VPN.";
        if (vpn.lastErrorMessage.length > 0) {
            self.hintLabel.text = [NSString stringWithFormat:@"%@\n%@", hint, vpn.lastErrorMessage];
        } else {
            self.hintLabel.text = hint;
        }
    } else if (vpn.isConnecting) {
        self.hintLabel.text = [NSString stringWithFormat:@"Этап: %@", SSTPLocalizedStage(vpn.stage)];
    }
}

#pragma mark - UITextFieldDelegate

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if (textField == self.serverField) {
        [self.usernameField becomeFirstResponder];
    } else if (textField == self.usernameField) {
        [self.passwordField becomeFirstResponder];
    } else {
        [self connectTapped];
    }
    return YES;
}

@end
