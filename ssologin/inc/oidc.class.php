<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Cliente OpenID Connect / OAuth 2.0 com PKCE (S256)
 *
 * Copyright (C) 2026 by G. Martins
 * ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of SSO Login.
 *
 * SSO Login is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SSO Login is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SSO Login. If not, see <https://www.gnu.org/licenses/>.
 * ------------------------------------------------------------------------
 */

if (!defined('GLPI_ROOT')) {
    die("Direct access not allowed.");
}

class PluginSsologinOidc
{
    public const FLOW_SESSION_KEY = 'plugin_ssologin_flow';
    public const FLOW_TTL_SECONDS = 600;
    public const CLOCK_SKEW_SECS  = 60;

    /** @var callable|null */
    private static $dnsResolver = null;

    /** @var callable|null */
    private static $httpClient = null;

    /**
     * Sets a custom DNS resolver callback (string $host): string[] for deterministic testing.
     *
     * @param callable|null $resolver
     */
    public static function setDnsResolver($resolver): void
    {
        self::$dnsResolver = is_callable($resolver) ? $resolver : null;
    }

    /**
     * Sets a custom HTTP transport callback (string $method, string $url, array $headers, string $body, int $timeout): array
     * returning ['status' => int, 'body' => string, 'error' => string].
     *
     * @param callable|null $client
     */
    public static function setHttpClient($client): void
    {
        self::$httpClient = is_callable($client) ? $client : null;
    }

    /**
     * Encodes binary or string data as RFC 4648 base64url without padding.
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodes RFC 4648 base64url string.
     */
    public static function base64UrlDecode(string $encoded): string
    {
        $remainder = strlen($encoded) % 4;
        if ($remainder > 0) {
            $encoded .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : '';
    }

    /**
     * Generates an OAuth 2.0 PKCE code_verifier and S256 code_challenge pair.
     *
     * @param string|null $customVerifier
     * @return array{verifier: string, challenge: string, method: string}
     */
    public static function generatePkcePair(?string $customVerifier = null): array
    {
        $verifier = ($customVerifier !== null && $customVerifier !== '')
            ? $customVerifier
            : self::base64UrlEncode(random_bytes(32));

        $challenge = self::base64UrlEncode(hash('sha256', $verifier, true));

        return [
            'verifier'  => $verifier,
            'challenge' => $challenge,
            'method'    => 'S256',
        ];
    }

    /**
     * Checks whether an IPv4 or IPv6 address is globally routable (blocks loopback, RFC1918,
     * link-local 169.254.0.0/16 metadata, CGNAT, multicast, and unspecified addresses).
     */
    public static function isPublicIp(string $ip): bool
    {
        $clean = trim($ip, '[] ');
        if ($clean === '') {
            return false;
        }

        if (stripos($clean, '::ffff:') === 0) {
            $mapped = substr($clean, 7);
            if (filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $clean = $mapped;
            }
        }

        if (filter_var($clean, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        if (filter_var($clean, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $long = ip2long($clean);
            if ($long === false) {
                return false;
            }
            $unsigned = (int) sprintf('%u', $long);

            $blockedCidrs = [
                ['0.0.0.0', 8],
                ['10.0.0.0', 8],
                ['100.64.0.0', 10],
                ['127.0.0.0', 8],
                ['169.254.0.0', 16],
                ['172.16.0.0', 12],
                ['192.0.0.0', 24],
                ['192.0.2.0', 24],
                ['192.168.0.0', 16],
                ['198.18.0.0', 15],
                ['198.51.100.0', 24],
                ['203.0.113.0', 24],
                ['224.0.0.0', 4],
                ['240.0.0.0', 4],
            ];

            foreach ($blockedCidrs as $cidr) {
                $netLong = (int) sprintf('%u', ip2long($cidr[0]));
                $bits    = (int) $cidr[1];
                $mask    = $bits === 0 ? 0 : ((~0 << (32 - $bits)) & 0xFFFFFFFF);
                if (($unsigned & $mask) === ($netLong & $mask)) {
                    return false;
                }
            }
        } else {
            $packed = @inet_pton($clean);
            if (!is_string($packed) || strlen($packed) !== 16) {
                return false;
            }
            $hex = strtolower(bin2hex($packed));
            if (
                $hex === str_repeat('0', 32)
                || $hex === str_repeat('0', 31) . '1'
                || strpos($hex, 'fe8') === 0
                || strpos($hex, 'fe9') === 0
                || strpos($hex, 'fea') === 0
                || strpos($hex, 'feb') === 0
                || strpos($hex, 'fc') === 0
                || strpos($hex, 'fd') === 0
                || strpos($hex, 'ff') === 0
                || strpos($hex, '20010db8') === 0
            ) {
                return false;
            }
        }

        return filter_var(
            $clean,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }

    /**
     * Strictly validates an IdP endpoint URL against SSRF and unsafe schemes.
     *
     * @param string $url
     * @param bool   $resolveDns
     * @return array{valid: bool, error: string, normalized: string}
     */
    public static function validateEndpointUrl(string $url, bool $resolveDns = true): array
    {
        $trimmed = trim($url);
        if ($trimmed === '' || preg_match('/[\x00-\x20\x7F]/', $trimmed)) {
            return ['valid' => false, 'error' => 'Empty or malformed URL.', 'normalized' => ''];
        }

        $parts = @parse_url($trimmed);
        if (!is_array($parts)) {
            return ['valid' => false, 'error' => 'Invalid URL syntax.', 'normalized' => ''];
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'https') {
            return ['valid' => false, 'error' => 'Only HTTPS endpoints are allowed.', 'normalized' => ''];
        }

        if (!empty($parts['user']) || !empty($parts['pass'])) {
            return ['valid' => false, 'error' => 'Embedded credentials in URL are not allowed.', 'normalized' => ''];
        }

        if (isset($parts['fragment'])) {
            return ['valid' => false, 'error' => 'URL fragments are not allowed.', 'normalized' => ''];
        }

        $rawHost = (string) ($parts['host'] ?? '');
        $host    = strtolower(trim($rawHost, '[] '));
        if ($host === '') {
            return ['valid' => false, 'error' => 'Missing URL host.', 'normalized' => ''];
        }

        if (
            $host === 'localhost'
            || substr($host, -10) === '.localhost'
            || substr($host, -6) === '.local'
            || substr($host, -9) === '.internal'
        ) {
            return ['valid' => false, 'error' => 'Localhost or internal domain is not allowed.', 'normalized' => ''];
        }

        if (ctype_digit($host) || preg_match('/^0x[0-9a-f]+$/i', $host)) {
            return ['valid' => false, 'error' => 'Numeric IP encoding is not allowed.', 'normalized' => ''];
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false || ip2long($host) !== false) {
            if (!self::isPublicIp($host)) {
                return [
                    'valid'      => false,
                    'error'      => 'Private, loopback, link-local, or reserved IP address is not allowed.',
                    'normalized' => '',
                ];
            }
            return ['valid' => true, 'error' => '', 'normalized' => $trimmed];
        }

        if (!preg_match('/^[a-z0-9.-]+$/', $host) || strpos($host, '..') !== false) {
            return ['valid' => false, 'error' => 'Invalid hostname characters.', 'normalized' => ''];
        }

        if ($resolveDns) {
            if (self::$dnsResolver !== null) {
                $ips = call_user_func(self::$dnsResolver, $host);
            } else {
                $ips = @gethostbynamel($host);
            }

            if (!is_array($ips) || $ips === []) {
                return [
                    'valid'      => false,
                    'error'      => 'Could not resolve IdP hostname via DNS.',
                    'normalized' => '',
                ];
            }

            foreach ($ips as $ip) {
                if (!is_string($ip) || !self::isPublicIp($ip)) {
                    return [
                        'valid'      => false,
                        'error'      => 'Hostname resolves to a disallowed private, loopback, or metadata IP.',
                        'normalized' => '',
                    ];
                }
            }
        }

        return ['valid' => true, 'error' => '', 'normalized' => $trimmed];
    }

    /**
     * Validates an internal post-login redirect target and rejects open redirects.
     */
    public static function sanitizeInternalRedirect(string $redirect): string
    {
        $clean = trim((string) preg_replace('/[\x00-\x1F\x7F]/', '', $redirect));
        if ($clean === '') {
            return '';
        }

        if (
            strpos($clean, '\\') !== false
            || strpos($clean, '//') === 0
            || strpos($clean, '://') !== false
            || strpos($clean, '@') !== false
            || preg_match('/^[a-zA-Z][a-zA-Z0-9+.-]*:/', $clean)
        ) {
            return '';
        }

        $parsed = @parse_url($clean);
        if (!is_array($parsed)) {
            return '';
        }

        if (!empty($parsed['scheme']) || !empty($parsed['host']) || !empty($parsed['user']) || !empty($parsed['pass'])) {
            return '';
        }

        if ($clean[0] !== '/') {
            $clean = '/' . ltrim($clean, '/');
        }

        if (strpos($clean, '//') === 0 || strpos($clean, '/\\') === 0) {
            return '';
        }

        return $clean;
    }

    /**
     * Builds the absolute OIDC callback URL for this GLPI instance.
     */
    public static function getCallbackUrl(): string
    {
        global $CFG_GLPI;

        $urlBase = trim((string) ($CFG_GLPI['url_base'] ?? ''));
        if ($urlBase !== '') {
            return PluginSsologinCompat::webPath(true) . '/front/callback.php';
        }

        $https  = !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';
        $scheme = $https ? 'https' : 'http';
        $host   = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');

        return $scheme . '://' . $host . PluginSsologinCompat::webPath(false) . '/front/callback.php';
    }

    /**
     * Starts an OAuth 2.0 / OIDC authorization flow with PKCE S256 and stores single-use session state.
     *
     * @param string   $requestedRedirect
     * @param int|null $now
     * @return array{ok: bool, error?: string, redirect_url?: string, state?: string, nonce?: string, code_challenge?: string}
     */
    public static function startAuthorizationFlow(string $requestedRedirect = '', ?int $now = null): array
    {
        $config = PluginSsologinConfig::getConfig();
        if ((int) ($config['enabled'] ?? 0) !== 1) {
            return ['ok' => false, 'error' => __('SSO Login is disabled.', 'ssologin')];
        }

        $clientId     = trim((string) ($config['client_id'] ?? ''));
        $authorizeUrl = trim((string) ($config['authorize_url'] ?? ''));
        $tokenUrl     = trim((string) ($config['token_url'] ?? ''));
        $scopes       = trim((string) ($config['scopes'] ?? 'openid profile email'));

        if ($clientId === '' || $authorizeUrl === '' || $tokenUrl === '') {
            return ['ok' => false, 'error' => __('SSO Login configuration is incomplete.', 'ssologin')];
        }

        $urlCheck = self::validateEndpointUrl($authorizeUrl, false);
        if (empty($urlCheck['valid'])) {
            return ['ok' => false, 'error' => (string) ($urlCheck['error'] ?? 'Invalid authorize URL.')];
        }

        $state        = bin2hex(random_bytes(32));
        $nonce        = bin2hex(random_bytes(32));
        $pkce         = self::generatePkcePair();
        $safeRedirect = self::sanitizeInternalRedirect($requestedRedirect);
        $timestamp    = $now ?? time();

        $_SESSION[self::FLOW_SESSION_KEY] = [
            'state'         => $state,
            'nonce'         => $nonce,
            'code_verifier' => $pkce['verifier'],
            'redirect'      => $safeRedirect,
            'created_at'    => $timestamp,
        ];

        $query = http_build_query([
            'response_type'         => 'code',
            'client_id'             => $clientId,
            'redirect_uri'          => self::getCallbackUrl(),
            'scope'                 => $scopes !== '' ? $scopes : 'openid profile email',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $pkce['challenge'],
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        $separator   = (strpos($authorizeUrl, '?') === false) ? '?' : '&';
        $redirectUrl = $authorizeUrl . $separator . $query;

        return [
            'ok'             => true,
            'redirect_url'   => $redirectUrl,
            'state'          => $state,
            'nonce'          => $nonce,
            'code_challenge' => $pkce['challenge'],
        ];
    }

    /**
     * Consumes and immediately invalidates the single-use OAuth2 session state (anti-replay).
     *
     * @param string   $receivedState
     * @param int|null $now
     * @return array{ok: bool, error?: string, flow?: array}
     */
    public static function consumeFlowState(string $receivedState, ?int $now = null): array
    {
        $flow = $_SESSION[self::FLOW_SESSION_KEY] ?? null;
        unset($_SESSION[self::FLOW_SESSION_KEY]);

        if (!is_array($flow)) {
            return ['ok' => false, 'error' => 'missing_flow_state'];
        }

        $expectedState = (string) ($flow['state'] ?? '');
        $nonce         = (string) ($flow['nonce'] ?? '');
        $verifier      = (string) ($flow['code_verifier'] ?? '');
        $createdAt     = (int) ($flow['created_at'] ?? 0);

        if ($expectedState === '' || $nonce === '' || $verifier === '' || $createdAt <= 0) {
            return ['ok' => false, 'error' => 'corrupted_flow_state'];
        }

        if ($receivedState === '' || !hash_equals($expectedState, $receivedState)) {
            return ['ok' => false, 'error' => 'state_mismatch'];
        }

        $currentTime = $now ?? time();
        $age         = $currentTime - $createdAt;
        if ($age > self::FLOW_TTL_SECONDS || $age < -self::CLOCK_SKEW_SECS) {
            return ['ok' => false, 'error' => 'state_expired'];
        }

        return ['ok' => true, 'flow' => $flow];
    }

    /**
     * Performs an HTTPS request to the IdP after anti-SSRF validation.
     *
     * @param string   $method
     * @param string   $url
     * @param string[] $headers
     * @param string   $body
     * @param int      $timeout
     * @return array{status: int, body: string, error: string}
     */
    public static function httpRequest(
        string $method,
        string $url,
        array $headers = [],
        string $body = '',
        int $timeout = 10
    ): array {
        $check = self::validateEndpointUrl($url, true);
        if (empty($check['valid'])) {
            return [
                'status' => 0,
                'body'   => '',
                'error'  => (string) ($check['error'] ?? 'Endpoint blocked by SSRF policy.'),
            ];
        }

        if (self::$httpClient !== null) {
            $resp = call_user_func(self::$httpClient, $method, $url, $headers, $body, $timeout);
            return [
                'status' => (int) ($resp['status'] ?? 0),
                'body'   => (string) ($resp['body'] ?? ''),
                'error'  => (string) ($resp['error'] ?? ''),
            ];
        }

        if (!function_exists('curl_init')) {
            return ['status' => 0, 'body' => '', 'error' => 'cURL extension is not available.'];
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return ['status' => 0, 'body' => '', 'error' => 'Failed to initialize cURL.'];
        }

        $opts = [
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_TIMEOUT        => max(3, min(30, $timeout)),
            CURLOPT_CONNECTTIMEOUT => max(2, min(10, $timeout)),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_USERAGENT      => 'GLPI-SsoLogin/' . (defined('PLUGIN_SSOLOGIN_VERSION') ? PLUGIN_SSOLOGIN_VERSION : '1.0.0'),
        ];

        if (defined('CURLPROTO_HTTPS')) {
            $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        if (strtoupper($method) === 'POST') {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }

        curl_setopt_array($ch, $opts);
        $rawBody = curl_exec($ch);
        $err     = curl_error($ch);
        $status  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [
            'status' => $status,
            'body'   => is_string($rawBody) ? $rawBody : '',
            'error'  => $err,
        ];
    }

    /**
     * Validates an OIDC ID Token JWT structure, signature (HS256 when applicable), and claims (iss, aud, exp, nbf, nonce).
     *
     * @param string   $idToken
     * @param array    $config
     * @param string   $expectedNonce
     * @param int|null $now
     * @param string   $clientSecret
     * @return array{ok: bool, error?: string, claims?: array, alg?: string}
     */
    public static function validateIdToken(
        string $idToken,
        array $config,
        string $expectedNonce,
        ?int $now = null,
        string $clientSecret = ''
    ): array {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return ['ok' => false, 'error' => 'malformed_jwt'];
        }

        list($headerB64, $payloadB64, $sigB64) = $parts;
        if ($headerB64 === '' || $payloadB64 === '' || $sigB64 === '') {
            return ['ok' => false, 'error' => 'unsigned_or_empty_jwt'];
        }

        $headerJson  = self::base64UrlDecode($headerB64);
        $payloadJson = self::base64UrlDecode($payloadB64);
        $signature   = self::base64UrlDecode($sigB64);

        $header = json_decode($headerJson, true);
        $claims = json_decode($payloadJson, true);

        if (!is_array($header) || !is_array($claims) || $signature === '') {
            return ['ok' => false, 'error' => 'invalid_jwt_encoding'];
        }

        $alg = strtoupper(trim((string) ($header['alg'] ?? '')));
        if ($alg === '' || $alg === 'NONE') {
            return ['ok' => false, 'error' => 'disallowed_jwt_alg'];
        }

        if ($alg === 'HS256') {
            if ($clientSecret === '') {
                return ['ok' => false, 'error' => 'missing_secret_for_hs256'];
            }
            $expectedSig = hash_hmac('sha256', $headerB64 . '.' . $payloadB64, $clientSecret, true);
            if (!hash_equals($expectedSig, $signature)) {
                return ['ok' => false, 'error' => 'invalid_jwt_signature'];
            }
        }

        $expectedIssuer = rtrim(trim((string) ($config['issuer_url'] ?? '')), '/');
        if ($expectedIssuer !== '') {
            $actualIssuer = rtrim(trim((string) ($claims['iss'] ?? '')), '/');
            if ($actualIssuer === '' || !hash_equals($expectedIssuer, $actualIssuer)) {
                return ['ok' => false, 'error' => 'issuer_mismatch'];
            }
        }

        $clientId = trim((string) ($config['client_id'] ?? ''));
        $aud      = $claims['aud'] ?? null;
        $audMatch = false;
        $audCount = 0;

        if (is_string($aud)) {
            $audCount = 1;
            $audMatch = ($clientId !== '' && hash_equals($clientId, $aud));
        } elseif (is_array($aud)) {
            $audCount = count($aud);
            foreach ($aud as $audItem) {
                if (is_string($audItem) && $clientId !== '' && hash_equals($clientId, $audItem)) {
                    $audMatch = true;
                    break;
                }
            }
        }

        if (!$audMatch) {
            return ['ok' => false, 'error' => 'audience_mismatch'];
        }

        if ($audCount > 1 || isset($claims['azp'])) {
            $azp = (string) ($claims['azp'] ?? '');
            if ($azp !== '' && !hash_equals($clientId, $azp)) {
                return ['ok' => false, 'error' => 'azp_mismatch'];
            }
        }

        $currentTime = $now ?? time();
        if (!isset($claims['exp']) || !is_numeric($claims['exp'])) {
            return ['ok' => false, 'error' => 'missing_exp_claim'];
        }
        if (((int) $claims['exp'] + self::CLOCK_SKEW_SECS) <= $currentTime) {
            return ['ok' => false, 'error' => 'token_expired'];
        }

        if (isset($claims['nbf']) && is_numeric($claims['nbf'])) {
            if (((int) $claims['nbf'] - self::CLOCK_SKEW_SECS) > $currentTime) {
                return ['ok' => false, 'error' => 'token_not_yet_valid'];
            }
        }

        $tokenNonce = isset($claims['nonce']) && is_string($claims['nonce']) ? $claims['nonce'] : '';
        if ($expectedNonce === '' || $tokenNonce === '' || !hash_equals($expectedNonce, $tokenNonce)) {
            return ['ok' => false, 'error' => 'nonce_mismatch'];
        }

        return [
            'ok'     => true,
            'claims' => $claims,
            'alg'    => $alg,
        ];
    }

    /**
     * Checks whether the email_verified claim explicitly indicates an unverified email.
     */
    public static function isEmailVerifiedClaim(array $claims): bool
    {
        if (!array_key_exists('email_verified', $claims)) {
            return true;
        }
        $val = $claims['email_verified'];
        if ($val === false || $val === 0 || $val === '0' || strtolower(trim((string) $val)) === 'false') {
            return false;
        }
        return true;
    }

    /**
     * Resolves a unique active GLPI user from validated OIDC claims.
     * Fails closed if >1 non-deleted user matches the email/username, or if user is inactive/deleted/expired/without profile.
     *
     * @param array    $claims
     * @param array    $config
     * @param int|null $now
     * @return array{ok: bool, error?: string, users_id?: int, identifier?: string}
     */
    public static function resolveGlpiUser(array $claims, array $config, ?int $now = null): array
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return ['ok' => false, 'error' => 'db_unavailable'];
        }

        $claimUsernameKey = trim((string) ($config['claim_username'] ?? 'preferred_username'));
        $claimEmailKey    = trim((string) ($config['claim_email'] ?? 'email'));
        $matchBy          = trim((string) ($config['match_by'] ?? 'both'));

        $rawUsername = '';
        if ($claimUsernameKey !== '' && isset($claims[$claimUsernameKey]) && is_scalar($claims[$claimUsernameKey])) {
            $rawUsername = trim((string) $claims[$claimUsernameKey]);
        }
        if ($rawUsername === '' && isset($claims['preferred_username']) && is_scalar($claims['preferred_username'])) {
            $rawUsername = trim((string) $claims['preferred_username']);
        }
        if ($rawUsername === '' && isset($claims['upn']) && is_scalar($claims['upn'])) {
            $rawUsername = trim((string) $claims['upn']);
        }

        $rawEmail = '';
        if ($claimEmailKey !== '' && isset($claims[$claimEmailKey]) && is_scalar($claims[$claimEmailKey])) {
            $rawEmail = strtolower(trim((string) $claims[$claimEmailKey]));
        }
        if ($rawEmail === '' && isset($claims['email']) && is_scalar($claims['email'])) {
            $rawEmail = strtolower(trim((string) $claims['email']));
        }

        $identifier = $rawEmail !== '' ? $rawEmail : ($rawUsername !== '' ? $rawUsername : (string) ($claims['sub'] ?? ''));

        $matchedUserIds = [];

        if (in_array($matchBy, ['both', 'username'], true) && $rawUsername !== '') {
            foreach (
                $DB->request([
                    'SELECT' => ['id'],
                    'FROM'   => 'glpi_users',
                    'WHERE'  => [
                        'name'       => PluginSsologinCompat::dbValues(['name' => $rawUsername])['name'],
                        'is_deleted' => 0,
                    ],
                ]) as $row
            ) {
                $uid = (int) ($row['id'] ?? 0);
                if ($uid > 0) {
                    $matchedUserIds[$uid] = true;
                }
            }
        }

        if (in_array($matchBy, ['both', 'email'], true) && $rawEmail !== '') {
            if (!self::isEmailVerifiedClaim($claims)) {
                return [
                    'ok'         => false,
                    'error'      => 'unverified_email',
                    'identifier' => $identifier,
                ];
            }

            $escapedEmail = PluginSsologinCompat::dbValues(['email' => $rawEmail])['email'];

            if (method_exists($DB, 'tableExists') && $DB->tableExists('glpi_useremails')) {
                $emailUserIds = [];
                foreach (
                    $DB->request([
                        'SELECT' => ['users_id'],
                        'FROM'   => 'glpi_useremails',
                        'WHERE'  => ['email' => $escapedEmail],
                    ]) as $erow
                ) {
                    $euid = (int) ($erow['users_id'] ?? 0);
                    if ($euid > 0) {
                        $emailUserIds[$euid] = true;
                    }
                }

                foreach (array_keys($emailUserIds) as $candidateId) {
                    foreach (
                        $DB->request([
                            'SELECT' => ['id'],
                            'FROM'   => 'glpi_users',
                            'WHERE'  => [
                                'id'         => $candidateId,
                                'is_deleted' => 0,
                            ],
                        ]) as $urow
                    ) {
                        $uid = (int) ($urow['id'] ?? 0);
                        if ($uid > 0) {
                            $matchedUserIds[$uid] = true;
                        }
                    }
                }
            }

            if ($matchedUserIds === []) {
                foreach (
                    $DB->request([
                        'SELECT' => ['id'],
                        'FROM'   => 'glpi_users',
                        'WHERE'  => [
                            'name'       => $escapedEmail,
                            'is_deleted' => 0,
                        ],
                    ]) as $urow
                ) {
                    $uid = (int) ($urow['id'] ?? 0);
                    if ($uid > 0) {
                        $matchedUserIds[$uid] = true;
                    }
                }
            }
        }

        $uniqueIds = array_keys($matchedUserIds);
        if (count($uniqueIds) === 0) {
            return [
                'ok'         => false,
                'error'      => 'user_not_found',
                'identifier' => $identifier,
            ];
        }

        if (count($uniqueIds) > 1) {
            return [
                'ok'         => false,
                'error'      => 'ambiguous_user',
                'identifier' => $identifier,
            ];
        }

        $targetUserId = (int) $uniqueIds[0];
        $userRow      = null;

        foreach (
            $DB->request([
                'SELECT' => ['id', 'name', 'is_active', 'is_deleted', 'begin_date', 'end_date'],
                'FROM'   => 'glpi_users',
                'WHERE'  => ['id' => $targetUserId],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            $userRow = $row;
        }

        if (!is_array($userRow)) {
            return ['ok' => false, 'error' => 'user_not_found', 'identifier' => $identifier];
        }

        if ((int) ($userRow['is_deleted'] ?? 0) !== 0 || (int) ($userRow['is_active'] ?? 0) !== 1) {
            return ['ok' => false, 'error' => 'user_inactive_or_deleted', 'identifier' => $identifier];
        }

        $currentTime = $now ?? time();
        $beginDate   = trim((string) ($userRow['begin_date'] ?? ''));
        if ($beginDate !== '' && $beginDate !== '0000-00-00 00:00:00') {
            $beginTs = strtotime($beginDate);
            if ($beginTs !== false && $beginTs > $currentTime) {
                return ['ok' => false, 'error' => 'user_not_yet_valid', 'identifier' => $identifier];
            }
        }

        $endDate = trim((string) ($userRow['end_date'] ?? ''));
        if ($endDate !== '' && $endDate !== '0000-00-00 00:00:00') {
            $endTs = strtotime($endDate);
            if ($endTs !== false && $endTs < $currentTime) {
                return ['ok' => false, 'error' => 'user_expired', 'identifier' => $identifier];
            }
        }

        $hasProfile = false;
        if (!method_exists($DB, 'tableExists') || $DB->tableExists('glpi_profiles_users')) {
            foreach (
                $DB->request([
                    'SELECT' => ['id'],
                    'FROM'   => 'glpi_profiles_users',
                    'WHERE'  => ['users_id' => $targetUserId],
                    'LIMIT'  => 1,
                ]) as $prow
            ) {
                if ((int) ($prow['id'] ?? 0) > 0) {
                    $hasProfile = true;
                }
            }
        }

        if (!$hasProfile) {
            return ['ok' => false, 'error' => 'user_no_profile', 'identifier' => $identifier];
        }

        return [
            'ok'         => true,
            'users_id'   => $targetUserId,
            'identifier' => $identifier,
        ];
    }

    /**
     * Handles the OAuth 2.0 / OIDC callback request end-to-end.
     *
     * @param array    $queryParams
     * @param int|null $now
     * @return array{ok: bool, error?: string, users_id?: int, redirect?: string}
     */
    public static function handleCallback(array $queryParams, ?int $now = null): array
    {
        $stateParam = isset($queryParams['state']) && is_string($queryParams['state'])
            ? trim($queryParams['state'])
            : '';

        $flowResult = self::consumeFlowState($stateParam, $now);

        if (!empty($queryParams['error'])) {
            $errCode = preg_replace('/[^a-zA-Z0-9_.-]/', '', (string) $queryParams['error']);
            self::logEvent('callback_error', 'error', 0, '', 'IdP returned error: ' . $errCode);
            return ['ok' => false, 'error' => 'idp_returned_error'];
        }

        if (empty($flowResult['ok']) || !isset($flowResult['flow']) || !is_array($flowResult['flow'])) {
            $reason = (string) ($flowResult['error'] ?? 'invalid_state');
            self::logEvent('state_validation_failed', 'warning', 0, '', 'OAuth state validation failed: ' . $reason);
            return ['ok' => false, 'error' => $reason];
        }

        $flow = $flowResult['flow'];
        $code = isset($queryParams['code']) && is_string($queryParams['code'])
            ? trim($queryParams['code'])
            : '';

        if ($code === '') {
            self::logEvent('missing_code', 'warning', 0, '', 'Missing authorization code on callback.');
            return ['ok' => false, 'error' => 'missing_code'];
        }

        $config       = PluginSsologinConfig::getConfig();
        $clientSecret = PluginSsologinConfig::getClientSecret();
        $tokenUrl     = trim((string) ($config['token_url'] ?? ''));
        $userinfoUrl  = trim((string) ($config['userinfo_url'] ?? ''));
        $timeout      = (int) ($config['timeout_seconds'] ?? 10);

        $postFields = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => self::getCallbackUrl(),
            'client_id'     => (string) ($config['client_id'] ?? ''),
            'code_verifier' => (string) $flow['code_verifier'],
        ];
        if ($clientSecret !== '') {
            $postFields['client_secret'] = $clientSecret;
        }

        $tokenResp = self::httpRequest(
            'POST',
            $tokenUrl,
            [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            http_build_query($postFields, '', '&', PHP_QUERY_RFC3986),
            $timeout
        );

        if ($tokenResp['status'] < 200 || $tokenResp['status'] >= 300 || $tokenResp['body'] === '') {
            self::logEvent('token_exchange_failed', 'error', 0, '', 'Token exchange failed with HTTP ' . $tokenResp['status']);
            return ['ok' => false, 'error' => 'token_exchange_failed'];
        }

        $tokenData = json_decode($tokenResp['body'], true);
        if (!is_array($tokenData)) {
            self::logEvent('token_invalid_json', 'error', 0, '', 'Token endpoint returned invalid JSON.');
            return ['ok' => false, 'error' => 'token_invalid_json'];
        }

        $idToken     = isset($tokenData['id_token']) && is_string($tokenData['id_token']) ? $tokenData['id_token'] : '';
        $accessToken = isset($tokenData['access_token']) && is_string($tokenData['access_token']) ? $tokenData['access_token'] : '';

        $claims = [];
        if ($idToken !== '') {
            $jwtCheck = self::validateIdToken(
                $idToken,
                $config,
                (string) $flow['nonce'],
                $now,
                $clientSecret
            );
            if (empty($jwtCheck['ok'])) {
                $err = (string) ($jwtCheck['error'] ?? 'invalid_id_token');
                self::logEvent('id_token_invalid', 'warning', 0, '', 'ID Token validation failed: ' . $err);
                return ['ok' => false, 'error' => $err];
            }
            $claims = $jwtCheck['claims'];
        }

        if ($userinfoUrl !== '') {
            if ($accessToken === '') {
                self::logEvent('missing_access_token', 'error', 0, '', 'Access token required for userinfo verification.');
                return ['ok' => false, 'error' => 'missing_access_token'];
            }

            $uResp = self::httpRequest(
                'GET',
                $userinfoUrl,
                [
                    'Authorization: Bearer ' . $accessToken,
                    'Accept: application/json',
                ],
                '',
                $timeout
            );

            if ($uResp['status'] < 200 || $uResp['status'] >= 300 || $uResp['body'] === '') {
                self::logEvent('userinfo_failed', 'error', 0, '', 'Userinfo endpoint failed with HTTP ' . $uResp['status']);
                return ['ok' => false, 'error' => 'userinfo_failed'];
            }

            $uData = json_decode($uResp['body'], true);
            if (!is_array($uData)) {
                self::logEvent('userinfo_invalid_json', 'error', 0, '', 'Userinfo endpoint returned invalid JSON.');
                return ['ok' => false, 'error' => 'userinfo_invalid_json'];
            }

            if (
                isset($claims['sub'], $uData['sub'])
                && is_string($claims['sub'])
                && is_string($uData['sub'])
                && !hash_equals($claims['sub'], $uData['sub'])
            ) {
                self::logEvent('sub_mismatch', 'warning', 0, '', 'Subject claim mismatch between id_token and userinfo.');
                return ['ok' => false, 'error' => 'sub_mismatch'];
            }

            $claims = array_merge($claims, $uData);
        } elseif ($idToken === '') {
            self::logEvent('no_identity_assertion', 'error', 0, '', 'Neither id_token nor userinfo_url provided claims.');
            return ['ok' => false, 'error' => 'no_identity_assertion'];
        }

        $resolution = self::resolveGlpiUser($claims, $config, $now);
        if (empty($resolution['ok'])) {
            $err        = (string) ($resolution['error'] ?? 'user_resolution_failed');
            $identifier = (string) ($resolution['identifier'] ?? '');
            self::logEvent('login_denied', 'warning', 0, $identifier, 'User resolution denied: ' . $err);
            return ['ok' => false, 'error' => $err];
        }

        $usersId    = (int) $resolution['users_id'];
        $identifier = (string) ($resolution['identifier'] ?? '');

        if (!self::completeGlpiLogin($usersId)) {
            self::logEvent('session_init_failed', 'error', $usersId, $identifier, 'Failed to initialize GLPI session.');
            return ['ok' => false, 'error' => 'session_init_failed'];
        }

        self::logEvent('login_success', 'ok', $usersId, $identifier, 'Authenticated via OIDC/OAuth2 SSO.');

        $safeRedirect = self::sanitizeInternalRedirect((string) ($flow['redirect'] ?? ''));

        return [
            'ok'       => true,
            'users_id' => $usersId,
            'redirect' => $safeRedirect,
        ];
    }

    /**
     * Initializes an authenticated GLPI session for the resolved user ID.
     */
    public static function completeGlpiLogin(int $usersId): bool
    {
        if ($usersId <= 0 || !class_exists('User') || !class_exists('Auth') || !class_exists('Session')) {
            return false;
        }

        $user = new User();
        if (!$user->getFromDB($usersId)) {
            return false;
        }

        $auth                = new Auth();
        $auth->user          = $user;
        $auth->auth_succeded = true;
        $auth->extauth       = 1;
        $auth->user_present  = 1;

        Session::init($auth);

        return true;
    }

    /**
     * Resolves client IP safely from REMOTE_ADDR.
     */
    public static function getClientIp(): string
    {
        $ip = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            return substr($ip, 0, 64);
        }
        return '';
    }

    /**
     * Writes an audit event to glpi_plugin_ssologin_logs.
     */
    public static function logEvent(
        string $eventType,
        string $status,
        int $usersId,
        string $identifier,
        string $summary
    ): void {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !method_exists($DB, 'tableExists')) {
            return;
        }
        if (!$DB->tableExists('glpi_plugin_ssologin_logs')) {
            return;
        }

        $row = PluginSsologinCompat::dbValues([
            'event_type'    => substr($eventType, 0, 64),
            'status'        => substr($status, 0, 16),
            'users_id'      => max(0, $usersId),
            'identifier'    => substr($identifier, 0, 191),
            'ip_address'    => self::getClientIp(),
            'summary'       => substr($summary, 0, 500),
            'date_creation' => date('Y-m-d H:i:s'),
        ]);

        $DB->insert('glpi_plugin_ssologin_logs', $row);
    }

    /**
     * Returns recent SSO audit log records.
     *
     * @param int $limit
     * @return array[]
     */
    public static function getRecentLogs(int $limit = 50): array
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !method_exists($DB, 'tableExists')) {
            return [];
        }
        if (!$DB->tableExists('glpi_plugin_ssologin_logs')) {
            return [];
        }

        $rows = [];
        foreach (
            $DB->request([
                'FROM'  => 'glpi_plugin_ssologin_logs',
                'ORDER' => 'id DESC',
                'LIMIT' => max(1, min(200, $limit)),
            ]) as $row
        ) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Purges audit logs older than the configured retention period.
     */
    public static function purgeOldLogs(int $retentionDays = 90): bool
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !method_exists($DB, 'tableExists')) {
            return false;
        }
        if (!$DB->tableExists('glpi_plugin_ssologin_logs')) {
            return false;
        }

        $days   = max(7, min(365, $retentionDays));
        $cutoff = date('Y-m-d H:i:s', time() - ($days * 86400));

        $DB->delete('glpi_plugin_ssologin_logs', [
            'date_creation' => ['<', $cutoff],
        ]);

        return true;
    }

    /**
     * Hook callback for display_login: renders the SSO login button on the GLPI login page.
     */
    public static function displayLoginButton(): void
    {
        $config = PluginSsologinConfig::getConfig();
        if ((int) ($config['enabled'] ?? 0) !== 1) {
            return;
        }

        $clientId     = trim((string) ($config['client_id'] ?? ''));
        $authorizeUrl = trim((string) ($config['authorize_url'] ?? ''));
        $tokenUrl     = trim((string) ($config['token_url'] ?? ''));

        if ($clientId === '' || $authorizeUrl === '' || $tokenUrl === '') {
            return;
        }

        $providerName = trim((string) ($config['provider_name'] ?? 'Single Sign-On'));
        if ($providerName === '') {
            $providerName = 'Single Sign-On';
        }

        $loginUrl = PluginSsologinCompat::webPath(false) . '/front/login.php';
        $redirect = isset($_GET['redirect']) && is_string($_GET['redirect'])
            ? self::sanitizeInternalRedirect($_GET['redirect'])
            : '';

        if ($redirect !== '') {
            $loginUrl .= '?redirect=' . rawurlencode($redirect);
        }

        $label = sprintf(__('Sign in with %s', 'ssologin'), $providerName);
        $safeHref  = htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8');
        $safeLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');

        echo '<div class="ssologin-login-container">';
        echo '<a class="btn btn-outline-primary ssologin-login-btn" href="' . $safeHref . '">';
        echo '<i class="fas fa-shield-alt ti ti-shield-lock ssologin-login-icon" aria-hidden="true"></i> ';
        echo '<span>' . $safeLabel . '</span>';
        echo '</a>';
        echo '</div>';
    }
}
