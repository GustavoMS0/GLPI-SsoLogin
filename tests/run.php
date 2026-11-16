<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Suite de testes automatizados (GLPI 10 / 11 / 12)
 *
 * Copyright (C) 2026 by G. Martins
 * Licensed under GPLv3+
 * ------------------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

$assertions = 0;

function assertTrue(bool $condition, string $message): void
{
    global $assertions;
    $assertions++;
    if (!$condition) {
        fwrite(STDERR, "[FAIL] " . $message . PHP_EOL);
        exit(1);
    }
}

function assertSame($expected, $actual, string $message): void
{
    global $assertions;
    $assertions++;
    if ($expected !== $actual) {
        fwrite(
            STDERR,
            sprintf(
                "[FAIL] %s (expected %s, got %s)%s",
                $message,
                var_export($expected, true),
                var_export($actual, true),
                PHP_EOL
            )
        );
        exit(1);
    }
}

function buildHs256Jwt(array $claims, string $secret, string $alg = 'HS256'): string
{
    $headerB64  = PluginSsologinOidc::base64UrlEncode((string) json_encode(['alg' => $alg, 'typ' => 'JWT']));
    $payloadB64 = PluginSsologinOidc::base64UrlEncode((string) json_encode($claims));
    if (strtoupper($alg) === 'NONE') {
        return $headerB64 . '.' . $payloadB64 . '.';
    }
    $sig    = hash_hmac('sha256', $headerB64 . '.' . $payloadB64, $secret, true);
    $sigB64 = PluginSsologinOidc::base64UrlEncode($sig);
    return $headerB64 . '.' . $payloadB64 . '.' . $sigB64;
}

// -------------------------------------------------------------------------
// 1. Version & Compatibility Helpers
// -------------------------------------------------------------------------
$isGlpi11Plus = version_compare((string) GLPI_VERSION, '11.0.0-dev', '>=');
$isGlpi12Plus = version_compare((string) GLPI_VERSION, '12.0.0-dev', '>=');

assertSame($isGlpi11Plus, PluginSsologinCompat::isGlpi11OrHigher(), 'isGlpi11OrHigher matches GLPI_VERSION');
assertSame(
    $isGlpi11Plus ? 'css/ssologin.css' : 'public/css/ssologin.css',
    PluginSsologinCompat::assetPath('css/ssologin.css'),
    'assetPath prefixes public/ only on GLPI < 11'
);
assertSame(
    '/glpi/plugins/ssologin',
    PluginSsologinCompat::webPath(false),
    'webPath returns /glpi/plugins/ssologin'
);
assertSame(
    'https://glpi.example.org/glpi/plugins/ssologin',
    PluginSsologinCompat::webPath(true),
    'webPath(true) returns full URL base path'
);

if ($isGlpi12Plus && version_compare(PHP_VERSION, '7.4.0', '>=')) {
    assertTrue(PluginSsologinCompat::typedRightname(), 'typedRightname is true on GLPI 12+');
} else {
    assertTrue(!PluginSsologinCompat::typedRightname(), 'typedRightname is false on GLPI 10/11');
}

// Verify fromCore preserves literal backslashes while decoding HTML entities on GLPI 10
$encodedEntityWithSlash = 'DOMAIN\\john.doe &amp; Co';
if (!$isGlpi11Plus) {
    assertSame(
        'DOMAIN\\john.doe & Co',
        PluginSsologinCompat::fromCore($encodedEntityWithSlash),
        'fromCore decodes HTML entities on GLPI 10 without stripping literal backslashes'
    );
} else {
    assertSame(
        $encodedEntityWithSlash,
        PluginSsologinCompat::fromCore($encodedEntityWithSlash),
        'fromCore returns value unchanged on GLPI 11+'
    );
}

// -------------------------------------------------------------------------
// 2. Hook initialization, Install & Uninstall (Modern DB & Legacy 10.0.5 DB)
// -------------------------------------------------------------------------
global $DB, $PLUGIN_HOOKS;
$PLUGIN_HOOKS = [];
plugin_init_ssologin();
assertTrue(!empty($PLUGIN_HOOKS['csrf_compliant']['ssologin']), 'csrf_compliant hook registered');
assertSame(
    [PluginSsologinOidc::class, 'displayLoginButton'],
    $PLUGIN_HOOKS['display_login']['ssologin'],
    'display_login hook registered'
);
assertSame(
    [PluginSsologinConfig::class, 'undiscloseConfigValue'],
    $PLUGIN_HOOKS['undiscloseConfigValue']['ssologin'],
    'undiscloseConfigValue hook registered'
);

assertTrue(plugin_ssologin_install(), 'plugin_ssologin_install succeeds on modern DB');
assertTrue($DB->tableExists('glpi_plugin_ssologin_logs'), 'glpi_plugin_ssologin_logs table created');

// Test GLPI 10.0.5 LegacyQueryOnlyDB without doQuery()
$savedDb = $DB;
$DB      = new LegacyQueryOnlyDB();
assertTrue(!method_exists($DB, 'doQuery'), 'LegacyQueryOnlyDB does not have doQuery');
assertTrue(plugin_ssologin_install(), 'plugin_ssologin_install succeeds on LegacyQueryOnlyDB');
assertTrue($DB->tableExists('glpi_plugin_ssologin_logs'), 'glpi_plugin_ssologin_logs created via query() fallback');
assertTrue(plugin_ssologin_uninstall(), 'plugin_ssologin_uninstall succeeds on LegacyQueryOnlyDB');
assertTrue(!$DB->tableExists('glpi_plugin_ssologin_logs'), 'glpi_plugin_ssologin_logs dropped on LegacyQueryOnlyDB');
$DB = $savedDb;

// -------------------------------------------------------------------------
// 3. AES-256-GCM Secret Encryption, Tamper Detection & Blank-Update Preservation
// -------------------------------------------------------------------------
$rawSecret = 'super-secret-oidc-client-secret-2026!@#';
$encrypted = PluginSsologinConfig::encryptSecret($rawSecret);
assertTrue(strpos($encrypted, 'v1:') === 0, 'Encrypted secret has v1: prefix');
assertTrue(strpos($encrypted, $rawSecret) === false, 'Encrypted payload never contains plaintext secret');
assertSame($rawSecret, PluginSsologinConfig::decryptSecret($encrypted), 'AES-256-GCM decrypts back to exact secret');

// Tamper with authentication tag
$parts    = explode(':', $encrypted, 4);
$tampered = $parts[0] . ':' . $parts[1] . ':' . base64_encode(random_bytes(16)) . ':' . $parts[3];
assertSame('', PluginSsologinConfig::decryptSecret($tampered), 'Tampered GCM auth tag fails closed');

// Save configuration with initial secret
$saveRes = PluginSsologinConfig::saveConfig([
    'enabled'                => '1',
    'provider_name'          => 'Corporate Entra ID',
    'client_id'              => 'glpi-oidc-client-01',
    'client_secret'          => $rawSecret,
    'issuer_url'             => 'https://idp.example.com/oauth2',
    'authorize_url'          => 'https://idp.example.com/oauth2/authorize',
    'token_url'              => 'https://idp.example.com/oauth2/token',
    'userinfo_url'           => 'https://idp.example.com/oauth2/userinfo',
    'scopes'                 => 'openid profile email',
    'claim_username'         => 'preferred_username',
    'claim_email'            => 'email',
    'match_by'               => 'both',
    'allow_jit_provisioning' => '0',
    'timeout_seconds'        => 10,
    'retention_days'         => 90,
]);
assertTrue($saveRes['ok'], 'saveConfig succeeds with valid HTTPS URLs');
assertSame($rawSecret, PluginSsologinConfig::getClientSecret(), 'getClientSecret returns initial secret');
assertTrue(PluginSsologinConfig::hasClientSecret(), 'hasClientSecret is true');

// Update configuration with blank client_secret -> must preserve existing encrypted secret!
$saveBlank = PluginSsologinConfig::saveConfig([
    'enabled'       => '1',
    'provider_name' => 'Corporate Keycloak',
    'client_id'     => 'glpi-oidc-client-01',
    'client_secret' => '',
    'issuer_url'    => 'https://idp.example.com/oauth2',
    'authorize_url' => 'https://idp.example.com/oauth2/authorize',
    'token_url'     => 'https://idp.example.com/oauth2/token',
    'userinfo_url'  => 'https://idp.example.com/oauth2/userinfo',
]);
assertTrue($saveBlank['ok'], 'saveConfig succeeds with blank client_secret');
assertSame($rawSecret, PluginSsologinConfig::getClientSecret(), 'Blank client_secret on update preserves stored encrypted secret');

// Verify undiscloseConfigValue masks client_secret_enc and secret_key
$discloseCheck = PluginSsologinConfig::undiscloseConfigValue([
    'context' => PluginSsologinConfig::CONTEXT,
    'name'    => 'client_secret_enc',
    'value'   => $encrypted,
]);
assertSame('', $discloseCheck['value'], 'undiscloseConfigValue masks client_secret_enc');

// -------------------------------------------------------------------------
// 4. SSRF & Endpoint URL Validation
// -------------------------------------------------------------------------
PluginSsologinOidc::setDnsResolver(function (string $host): array {
    $map = [
        'idp.example.com'      => ['93.184.216.34'],
        'rebind-loopback.test' => ['127.0.0.1'],
        'rebind-metadata.test' => ['169.254.169.254'],
        'rebind-private.test'  => ['10.20.30.40'],
    ];
    return $map[$host] ?? [];
});

$ssrfCases = [
    'http://idp.example.com/oauth2/token'            => false,
    'https://user:pass@idp.example.com/oauth2/token' => false,
    'https://localhost/oauth2/token'                 => false,
    'https://sub.localhost/oauth2/token'             => false,
    'https://127.0.0.1/oauth2/token'                 => false,
    'https://[::1]/oauth2/token'                     => false,
    'https://169.254.169.254/latest/meta-data/'      => false,
    'https://10.0.0.1/oauth2/token'                  => false,
    'https://172.16.0.10/oauth2/token'               => false,
    'https://192.168.1.1/oauth2/token'               => false,
    'https://0.0.0.0/oauth2/token'                   => false,
    'https://rebind-loopback.test/oauth2/token'      => false,
    'https://rebind-metadata.test/oauth2/token'      => false,
    'https://rebind-private.test/oauth2/token'       => false,
    'https://idp.example.com/oauth2/token'           => true,
];

foreach ($ssrfCases as $testUrl => $expectedValid) {
    $res = PluginSsologinOidc::validateEndpointUrl($testUrl, true);
    assertSame(
        $expectedValid,
        $res['valid'],
        'SSRF validation for ' . $testUrl
    );
}

// Also verify saveConfig rejects SSRF / non-HTTPS URLs
$badConfigSave = PluginSsologinConfig::saveConfig([
    'enabled'       => '1',
    'client_id'     => 'cid',
    'authorize_url' => 'http://idp.example.com/authorize',
    'token_url'     => 'https://169.254.169.254/token',
]);
assertTrue(!$badConfigSave['ok'], 'saveConfig rejects non-HTTPS and metadata URLs');

// -------------------------------------------------------------------------
// 5. Open Redirect Sanitization
// -------------------------------------------------------------------------
$redirectCases = [
    '//evil.com/phish'               => '',
    '///evil.com'                    => '',
    '/\\evil.com'                    => '',
    'https://evil.com/login'         => '',
    'http://evil.com'                => '',
    'javascript:alert(1)'            => '',
    'data:text/html,<script>'        => '',
    'https://glpi.example.org@evil'  => '',
    '/front/ticket.form.php?id=42'   => '/front/ticket.form.php?id=42',
    'front/central.php'              => '/front/central.php',
];

foreach ($redirectCases as $inputRedir => $expectedRedir) {
    assertSame(
        $expectedRedir,
        PluginSsologinOidc::sanitizeInternalRedirect($inputRedir),
        'sanitizeInternalRedirect for ' . $inputRedir
    );
}

// -------------------------------------------------------------------------
// 6. PKCE S256 Generation
// -------------------------------------------------------------------------
// RFC 7636 Appendix B test vector
$rfcVerifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
$rfcChallenge = 'E9Melhoa2OwvFrZpTJguCHaoeK1t8URWbuGJSstw-cM';
$pkceRfc      = PluginSsologinOidc::generatePkcePair($rfcVerifier);
assertSame($rfcChallenge, $pkceRfc['challenge'], 'PKCE S256 matches RFC 7636 test vector');
assertSame('S256', $pkceRfc['method'], 'PKCE method is S256');

$pkceRandom = PluginSsologinOidc::generatePkcePair();
assertSame(43, strlen($pkceRandom['verifier']), 'Random PKCE verifier is 43 chars base64url');
assertSame(43, strlen($pkceRandom['challenge']), 'Random PKCE challenge is 43 chars base64url');
assertTrue(strpos($pkceRandom['challenge'], '=') === false, 'PKCE challenge has no padding');

// -------------------------------------------------------------------------
// 7. Single-Use State, Replay Rejection & TTL Expiration
// -------------------------------------------------------------------------
$_SESSION = [];
$now      = 1700000000;

$flowStart = PluginSsologinOidc::startAuthorizationFlow('//evil.com/attack', $now);
assertTrue($flowStart['ok'], 'startAuthorizationFlow succeeds');
assertSame('', $_SESSION[PluginSsologinOidc::FLOW_SESSION_KEY]['redirect'], 'Malicious redirect stripped in session flow');

$validState = (string) $flowStart['state'];
$consumeOk  = PluginSsologinOidc::consumeFlowState($validState, $now + 30);
assertTrue($consumeOk['ok'], 'First consumption of valid state succeeds');
assertTrue(!isset($_SESSION[PluginSsologinOidc::FLOW_SESSION_KEY]), 'Session flow state immediately unset upon consumption');

// Replay attempt with the exact same state must fail
$replayAttempt = PluginSsologinOidc::consumeFlowState($validState, $now + 31);
assertTrue(!$replayAttempt['ok'], 'Replay of consumed state is rejected');
assertSame('missing_flow_state', $replayAttempt['error'], 'Replay returns missing_flow_state');

// Wrong state attempt destroys stored state immediately (anti-brute-force)
$flowStart2 = PluginSsologinOidc::startAuthorizationFlow('/front/ticket.php', $now);
$wrongCheck = PluginSsologinOidc::consumeFlowState('wrong-state-value', $now + 5);
assertTrue(!$wrongCheck['ok'], 'Mismatched state rejected');
assertSame('state_mismatch', $wrongCheck['error'], 'Error is state_mismatch');
$secondTryAfterWrong = PluginSsologinOidc::consumeFlowState((string) $flowStart2['state'], $now + 6);
assertTrue(!$secondTryAfterWrong['ok'], 'Session flow state was destroyed on first invalid state attempt');

// Expired state (> 600s) rejected
$flowStart3   = PluginSsologinOidc::startAuthorizationFlow('/front/central.php', $now);
$expiredCheck = PluginSsologinOidc::consumeFlowState((string) $flowStart3['state'], $now + 601);
assertTrue(!$expiredCheck['ok'], 'Expired state (>600s) rejected');
assertSame('state_expired', $expiredCheck['error'], 'Error is state_expired');

// -------------------------------------------------------------------------
// 8. ID Token Validation (iss, aud, exp, nonce, alg)
// -------------------------------------------------------------------------
$cfg = PluginSsologinConfig::getConfig();
$baseClaims = [
    'iss'   => 'https://idp.example.com/oauth2',
    'sub'   => 'sub-user-101',
    'aud'   => 'glpi-oidc-client-01',
    'exp'   => $now + 300,
    'iat'   => $now,
    'nonce' => 'nonce-xyz-987',
    'email' => 'alice@example.org',
];

$validJwt = buildHs256Jwt($baseClaims, $rawSecret);
$jwtOk    = PluginSsologinOidc::validateIdToken($validJwt, $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue($jwtOk['ok'], 'Valid HS256 JWT passes validation');

// alg=none rejected
$noneJwt = buildHs256Jwt($baseClaims, $rawSecret, 'none');
$jwtNone = PluginSsologinOidc::validateIdToken($noneJwt, $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue(!$jwtNone['ok'], 'alg=none JWT rejected');

// Wrong signature rejected
$badSigJwt = buildHs256Jwt($baseClaims, 'wrong-secret');
$jwtBadSig = PluginSsologinOidc::validateIdToken($badSigJwt, $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue(!$jwtBadSig['ok'], 'Invalid HS256 signature rejected');
assertSame('invalid_jwt_signature', $jwtBadSig['error'], 'Error is invalid_jwt_signature');

// Wrong issuer rejected
$badIssClaims        = $baseClaims;
$badIssClaims['iss'] = 'https://evil-idp.example.com';
$jwtBadIss           = PluginSsologinOidc::validateIdToken(buildHs256Jwt($badIssClaims, $rawSecret), $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue(!$jwtBadIss['ok'], 'Mismatched issuer rejected');
assertSame('issuer_mismatch', $jwtBadIss['error'], 'Error is issuer_mismatch');

// Wrong audience rejected
$badAudClaims        = $baseClaims;
$badAudClaims['aud'] = 'other-app-client-id';
$jwtBadAud           = PluginSsologinOidc::validateIdToken(buildHs256Jwt($badAudClaims, $rawSecret), $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue(!$jwtBadAud['ok'], 'Mismatched audience rejected');
assertSame('audience_mismatch', $jwtBadAud['error'], 'Error is audience_mismatch');

// Expired token rejected
$expClaims        = $baseClaims;
$expClaims['exp'] = $now - 120;
$jwtExp           = PluginSsologinOidc::validateIdToken(buildHs256Jwt($expClaims, $rawSecret), $cfg, 'nonce-xyz-987', $now, $rawSecret);
assertTrue(!$jwtExp['ok'], 'Expired JWT rejected');
assertSame('token_expired', $jwtExp['error'], 'Error is token_expired');

// Wrong nonce rejected
$jwtBadNonce = PluginSsologinOidc::validateIdToken($validJwt, $cfg, 'different-nonce', $now, $rawSecret);
assertTrue(!$jwtBadNonce['ok'], 'Mismatched nonce rejected');
assertSame('nonce_mismatch', $jwtBadNonce['error'], 'Error is nonce_mismatch');

// -------------------------------------------------------------------------
// 9. User Resolution Guards & End-to-End Callback Flow
// -------------------------------------------------------------------------
// Populate test users in FakeTestDB
$DB->tables['glpi_users'] = [
    [
        'id'         => 10,
        'name'       => 'alice',
        'is_active'  => 1,
        'is_deleted' => 0,
        'begin_date' => null,
        'end_date'   => null,
    ],
    [
        'id'         => 20,
        'name'       => 'dup_user_1',
        'is_active'  => 1,
        'is_deleted' => 0,
        'begin_date' => null,
        'end_date'   => null,
    ],
    [
        'id'         => 21,
        'name'       => 'dup_user_2',
        'is_active'  => 1,
        'is_deleted' => 0,
        'begin_date' => null,
        'end_date'   => null,
    ],
    [
        'id'         => 30,
        'name'       => 'inactive_bob',
        'is_active'  => 0,
        'is_deleted' => 0,
        'begin_date' => null,
        'end_date'   => null,
    ],
    [
        'id'         => 31,
        'name'       => 'deleted_charlie',
        'is_active'  => 1,
        'is_deleted' => 1,
        'begin_date' => null,
        'end_date'   => null,
    ],
    [
        'id'         => 40,
        'name'       => 'noprofile_dave',
        'is_active'  => 1,
        'is_deleted' => 0,
        'begin_date' => null,
        'end_date'   => null,
    ],
];

$DB->tables['glpi_useremails'] = [
    ['id' => 1, 'users_id' => 10, 'email' => 'alice@example.org'],
    ['id' => 2, 'users_id' => 20, 'email' => 'shared@example.org'],
    ['id' => 3, 'users_id' => 21, 'email' => 'shared@example.org'],
    ['id' => 4, 'users_id' => 30, 'email' => 'bob@example.org'],
    ['id' => 5, 'users_id' => 31, 'email' => 'charlie@example.org'],
    ['id' => 6, 'users_id' => 40, 'email' => 'dave@example.org'],
];

$DB->tables['glpi_profiles_users'] = [
    ['id' => 1, 'users_id' => 10, 'profiles_id' => 4, 'entities_id' => 0],
    ['id' => 2, 'users_id' => 20, 'profiles_id' => 4, 'entities_id' => 0],
    ['id' => 3, 'users_id' => 21, 'profiles_id' => 4, 'entities_id' => 0],
    ['id' => 4, 'users_id' => 30, 'profiles_id' => 4, 'entities_id' => 0],
    ['id' => 5, 'users_id' => 31, 'profiles_id' => 4, 'entities_id' => 0],
];

// 9a. Unverified email rejected
$unverifiedRes = PluginSsologinOidc::resolveGlpiUser([
    'email'          => 'alice@example.org',
    'email_verified' => false,
], $cfg, $now);
assertTrue(!$unverifiedRes['ok'], 'email_verified=false rejected');
assertSame('unverified_email', $unverifiedRes['error'], 'Error is unverified_email');

// 9b. Ambiguous email lookup (>1 active user sharing email) fails closed
$ambiguousRes = PluginSsologinOidc::resolveGlpiUser([
    'email'          => 'shared@example.org',
    'email_verified' => true,
], $cfg, $now);
assertTrue(!$ambiguousRes['ok'], 'Ambiguous email lookup fails closed');
assertSame('ambiguous_user', $ambiguousRes['error'], 'Error is ambiguous_user');

// 9c. Inactive user rejected
$inactiveRes = PluginSsologinOidc::resolveGlpiUser([
    'preferred_username' => 'inactive_bob',
], $cfg, $now);
assertTrue(!$inactiveRes['ok'], 'Inactive user rejected');
assertSame('user_inactive_or_deleted', $inactiveRes['error'], 'Error is user_inactive_or_deleted');

// 9d. Deleted user rejected
$deletedRes = PluginSsologinOidc::resolveGlpiUser([
    'preferred_username' => 'deleted_charlie',
], $cfg, $now);
assertTrue(!$deletedRes['ok'], 'Deleted user rejected');
assertSame('user_not_found', $deletedRes['error'], 'Deleted user is ignored during lookup');

// 9e. User without profile rejected
$noProfileRes = PluginSsologinOidc::resolveGlpiUser([
    'preferred_username' => 'noprofile_dave',
], $cfg, $now);
assertTrue(!$noProfileRes['ok'], 'User without profile rejected');
assertSame('user_no_profile', $noProfileRes['error'], 'Error is user_no_profile');

// 9f. End-to-End Callback Success & Session Initialization
$e2eStart  = PluginSsologinOidc::startAuthorizationFlow('/front/ticket.form.php?id=99', $now);
$e2eState  = (string) $e2eStart['state'];
$e2eNonce  = (string) $e2eStart['nonce'];

PluginSsologinOidc::setHttpClient(function (string $method, string $url, array $headers, string $body, int $timeout) use ($e2eNonce, $now, $rawSecret): array {
    if (strpos($url, '/oauth2/token') !== false) {
        $idToken = buildHs256Jwt([
            'iss'                => 'https://idp.example.com/oauth2',
            'sub'                => 'sub-alice-10',
            'aud'                => 'glpi-oidc-client-01',
            'exp'                => $now + 300,
            'iat'                => $now,
            'nonce'              => $e2eNonce,
            'preferred_username' => 'alice',
            'email'              => 'alice@example.org',
            'email_verified'     => true,
        ], $rawSecret);

        return [
            'status' => 200,
            'body'   => (string) json_encode([
                'access_token' => 'access-token-alice-xyz',
                'token_type'   => 'Bearer',
                'id_token'     => $idToken,
            ]),
            'error'  => '',
        ];
    }

    if (strpos($url, '/oauth2/userinfo') !== false) {
        return [
            'status' => 200,
            'body'   => (string) json_encode([
                'sub'                => 'sub-alice-10',
                'preferred_username' => 'alice',
                'email'              => 'alice@example.org',
                'email_verified'     => true,
            ]),
            'error'  => '',
        ];
    }

    return ['status' => 404, 'body' => '', 'error' => 'Not found'];
});

Session::$initializedAuth = null;
$cbResult = PluginSsologinOidc::handleCallback([
    'state' => $e2eState,
    'code'  => 'auth-code-123456',
], $now + 10);

assertTrue($cbResult['ok'], 'End-to-end callback succeeds for valid user');
assertSame(10, $cbResult['users_id'], 'Resolved users_id is 10');
assertSame('/front/ticket.form.php?id=99', $cbResult['redirect'], 'Internal redirect preserved');
assertTrue(Session::$initializedAuth instanceof Auth, 'Session::init called with Auth instance');
assertTrue(Session::$initializedAuth->auth_succeded === true, 'Auth::auth_succeded is true');
assertSame(10, (int) Session::$initializedAuth->user->fields['id'], 'Authenticated user ID in Session is 10');

$logs = PluginSsologinOidc::getRecentLogs(10);
assertTrue(count($logs) >= 1, 'Audit log recorded');
assertSame('login_success', $logs[0]['event_type'], 'Latest audit log is login_success');

// 9g. Subject mismatch between id_token and userinfo must fail closed
$subStart = PluginSsologinOidc::startAuthorizationFlow('/front/central.php', $now);
$subState = (string) $subStart['state'];
$subNonce = (string) $subStart['nonce'];

PluginSsologinOidc::setHttpClient(function (string $method, string $url) use ($subNonce, $now, $rawSecret): array {
    if (strpos($url, '/oauth2/token') !== false) {
        $idToken = buildHs256Jwt([
            'iss'   => 'https://idp.example.com/oauth2',
            'sub'   => 'sub-alice-10',
            'aud'   => 'glpi-oidc-client-01',
            'exp'   => $now + 300,
            'nonce' => $subNonce,
        ], $rawSecret);
        return [
            'status' => 200,
            'body'   => (string) json_encode(['access_token' => 'tok', 'id_token' => $idToken]),
            'error'  => '',
        ];
    }
    return [
        'status' => 200,
        'body'   => (string) json_encode(['sub' => 'sub-attacker-999', 'email' => 'alice@example.org']),
        'error'  => '',
    ];
});

$subMismatchRes = PluginSsologinOidc::handleCallback([
    'state' => $subState,
    'code'  => 'auth-code-sub-mismatch',
], $now + 5);
assertTrue(!$subMismatchRes['ok'], 'Subject mismatch between id_token and userinfo is rejected');
assertSame('sub_mismatch', $subMismatchRes['error'], 'Error is sub_mismatch');

// -------------------------------------------------------------------------
// 10. Subprocess matrix verification for GLPI 10.0.18, 11.0.0, and 12.0.0
// -------------------------------------------------------------------------
if (getenv('TEST_SUBPROCESS_CHILD') !== '1' && defined('PHP_BINARY') && is_string(PHP_BINARY) && PHP_BINARY !== '') {
    $matrix = [
        ['version' => '10.0.18', 'typed' => '0'],
        ['version' => '11.0.0',  'typed' => '0'],
        ['version' => '12.0.0',  'typed' => '1'],
    ];

    foreach ($matrix as $envCfg) {
        $cmd = sprintf(
            '%s -d display_errors=1 %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg(__FILE__)
        );
        putenv('TEST_SUBPROCESS_CHILD=1');
        putenv('TEST_GLPI_VERSION=' . $envCfg['version']);
        putenv('TEST_GLPI_TYPED_RIGHTNAME=' . $envCfg['typed']);

        $output   = [];
        $exitCode = 0;
        exec($cmd, $output, $exitCode);

        putenv('TEST_SUBPROCESS_CHILD');
        putenv('TEST_GLPI_VERSION');
        putenv('TEST_GLPI_TYPED_RIGHTNAME');

        assertSame(
            0,
            $exitCode,
            'Subprocess test for GLPI ' . $envCfg['version'] . ' exited cleanly: ' . implode("\n", $output)
        );
    }
}

echo sprintf(
    "[PASS] GLPI-SsoLogin tests passed (%d assertions on GLPI %s / PHP %s)%s",
    $assertions,
    GLPI_VERSION,
    PHP_VERSION,
    PHP_EOL
);
