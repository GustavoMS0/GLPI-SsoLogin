<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Configuracao global e criptografia de segredo OAuth2/OIDC
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

interface PluginSsologinConfigConstants
{
    public const CONTEXT = 'plugin:ssologin';
    public const CIPHER  = 'aes-256-gcm';
    public const AAD     = 'ssologin:client_secret:v1';
}

trait PluginSsologinConfigBody
{
    public static function getTypeName($nb = 0)
    {
        return __('SSO Login', 'ssologin');
    }

    /**
     * Default configuration values for plugin:ssologin.
     */
    public static function defaults(): array
    {
        return [
            'enabled'                => '0',
            'provider_name'          => 'Single Sign-On',
            'client_id'              => '',
            'client_secret_enc'      => '',
            'secret_key'             => '',
            'issuer_url'             => '',
            'authorize_url'          => '',
            'token_url'              => '',
            'userinfo_url'           => '',
            'scopes'                 => 'openid profile email',
            'claim_username'         => 'preferred_username',
            'claim_email'            => 'email',
            'match_by'               => 'both',
            'allow_jit_provisioning' => '0',
            'timeout_seconds'        => '10',
            'retention_days'         => '90',
        ];
    }

    /**
     * Returns merged configuration values with safe types and decoded strings.
     */
    public static function getConfig(): array
    {
        $defaults = self::defaults();
        $stored   = [];

        if (class_exists('Config') && method_exists('Config', 'getConfigurationValues')) {
            $raw = Config::getConfigurationValues(self::CONTEXT);
            if (is_array($raw)) {
                $stored = $raw;
            }
        }

        $merged = array_merge($defaults, $stored);
        $textKeys = [
            'provider_name',
            'client_id',
            'issuer_url',
            'authorize_url',
            'token_url',
            'userinfo_url',
            'scopes',
            'claim_username',
            'claim_email',
            'match_by',
        ];

        foreach ($textKeys as $k) {
            $merged[$k] = PluginSsologinCompat::fromCore((string) ($merged[$k] ?? ''));
        }

        $merged['enabled']                = ((int) ($merged['enabled'] ?? 0) === 1) ? 1 : 0;
        $merged['allow_jit_provisioning'] = ((int) ($merged['allow_jit_provisioning'] ?? 0) === 1) ? 1 : 0;

        $timeout = (int) ($merged['timeout_seconds'] ?? 10);
        if ($timeout < 3) {
            $timeout = 3;
        } elseif ($timeout > 30) {
            $timeout = 30;
        }
        $merged['timeout_seconds'] = $timeout;

        $retention = (int) ($merged['retention_days'] ?? 90);
        if ($retention < 7) {
            $retention = 7;
        } elseif ($retention > 365) {
            $retention = 365;
        }
        $merged['retention_days'] = $retention;

        if (!in_array($merged['match_by'], ['both', 'email', 'username'], true)) {
            $merged['match_by'] = 'both';
        }

        return $merged;
    }

    /**
     * Retrieves or initializes the per-install 256-bit encryption key.
     */
    private static function getEncryptionKey(): string
    {
        $raw = [];
        if (class_exists('Config') && method_exists('Config', 'getConfigurationValues')) {
            $cfg = Config::getConfigurationValues(self::CONTEXT);
            if (is_array($cfg)) {
                $raw = $cfg;
            }
        }

        $hexKey = isset($raw['secret_key']) ? trim((string) $raw['secret_key']) : '';
        if (strlen($hexKey) !== 64 || !ctype_xdigit($hexKey)) {
            $hexKey = bin2hex(random_bytes(32));
            if (class_exists('Config') && method_exists('Config', 'setConfigurationValues')) {
                Config::setConfigurationValues(self::CONTEXT, ['secret_key' => $hexKey]);
            }
        }

        $pepper = defined('GLPIKEY') ? (string) GLPIKEY : 'glpi-ssologin-install-pepper-v1';
        return hash_hmac('sha256', (string) hex2bin($hexKey), $pepper, true);
    }

    /**
     * Encrypts a client secret with AES-256-GCM and authenticated data.
     */
    public static function encryptSecret(string $plain): string
    {
        if ($plain === '') {
            return '';
        }

        $key = self::getEncryptionKey();
        $iv  = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plain,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::AAD,
            16
        );

        if ($ciphertext === false || strlen($tag) !== 16) {
            return '';
        }

        return 'v1:' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($ciphertext);
    }

    /**
     * Decrypts an AES-256-GCM encrypted client secret.
     */
    public static function decryptSecret(string $encoded): string
    {
        if ($encoded === '' || strpos($encoded, 'v1:') !== 0) {
            return '';
        }

        $parts = explode(':', $encoded, 4);
        if (count($parts) !== 4) {
            return '';
        }

        $iv         = base64_decode($parts[1], true);
        $tag        = base64_decode($parts[2], true);
        $ciphertext = base64_decode($parts[3], true);

        if (
            !is_string($iv)
            || strlen($iv) !== 12
            || !is_string($tag)
            || strlen($tag) !== 16
            || !is_string($ciphertext)
            || $ciphertext === ''
        ) {
            return '';
        }

        $key   = self::getEncryptionKey();
        $plain = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::AAD
        );

        return is_string($plain) ? $plain : '';
    }

    /**
     * Returns the decrypted client_secret at runtime.
     */
    public static function getClientSecret(): string
    {
        $cfg = self::getConfig();
        $enc = isset($cfg['client_secret_enc']) ? (string) $cfg['client_secret_enc'] : '';
        return self::decryptSecret($enc);
    }

    /**
     * Checks whether a valid non-empty client_secret is currently stored.
     */
    public static function hasClientSecret(): bool
    {
        return self::getClientSecret() !== '';
    }

    /**
     * Validates and saves plugin configuration.
     *
     * @param array $input
     * @return array{ok: bool, errors: string[]}
     */
    public static function saveConfig(array $input): array
    {
        $current = self::getConfig();
        $errors  = [];

        $enabled       = !empty($input['enabled']) ? '1' : '0';
        $providerName  = substr(trim((string) ($input['provider_name'] ?? 'Single Sign-On')), 0, 100);
        if ($providerName === '') {
            $providerName = 'Single Sign-On';
        }

        $clientId      = substr(trim((string) ($input['client_id'] ?? '')), 0, 255);
        $issuerUrl     = trim((string) ($input['issuer_url'] ?? ''));
        $authorizeUrl  = trim((string) ($input['authorize_url'] ?? ''));
        $tokenUrl      = trim((string) ($input['token_url'] ?? ''));
        $userinfoUrl   = trim((string) ($input['userinfo_url'] ?? ''));
        $scopes        = substr(trim((string) ($input['scopes'] ?? 'openid profile email')), 0, 255);
        if ($scopes === '') {
            $scopes = 'openid profile email';
        }

        $claimUsername = preg_replace('/[^a-zA-Z0-9_.:-]/', '', trim((string) ($input['claim_username'] ?? 'preferred_username')));
        if ($claimUsername === '') {
            $claimUsername = 'preferred_username';
        }

        $claimEmail = preg_replace('/[^a-zA-Z0-9_.:-]/', '', trim((string) ($input['claim_email'] ?? 'email')));
        if ($claimEmail === '') {
            $claimEmail = 'email';
        }

        $matchBy = trim((string) ($input['match_by'] ?? 'both'));
        if (!in_array($matchBy, ['both', 'email', 'username'], true)) {
            $matchBy = 'both';
        }

        $allowJit = !empty($input['allow_jit_provisioning']) ? '1' : '0';

        $timeout = (int) ($input['timeout_seconds'] ?? 10);
        if ($timeout < 3) {
            $timeout = 3;
        } elseif ($timeout > 30) {
            $timeout = 30;
        }

        $retention = (int) ($input['retention_days'] ?? 90);
        if ($retention < 7) {
            $retention = 7;
        } elseif ($retention > 365) {
            $retention = 365;
        }

        $urlFields = [
            'issuer_url'    => $issuerUrl,
            'authorize_url' => $authorizeUrl,
            'token_url'     => $tokenUrl,
            'userinfo_url'  => $userinfoUrl,
        ];

        foreach ($urlFields as $field => $urlValue) {
            if ($urlValue === '') {
                continue;
            }
            $check = PluginSsologinOidc::validateEndpointUrl($urlValue, false);
            if (empty($check['valid'])) {
                $errors[] = sprintf(
                    __('Invalid URL for %1$s: %2$s', 'ssologin'),
                    $field,
                    (string) ($check['error'] ?? '')
                );
            }
        }

        if ($enabled === '1') {
            if ($clientId === '') {
                $errors[] = __('Client ID is required when SSO is enabled.', 'ssologin');
            }
            if ($authorizeUrl === '' || $tokenUrl === '') {
                $errors[] = __('Authorize URL and Token URL are required when SSO is enabled.', 'ssologin');
            }
        }

        if ($errors !== []) {
            return ['ok' => false, 'errors' => $errors];
        }

        $secretEnc = (string) ($current['client_secret_enc'] ?? '');
        $newSecret = isset($input['client_secret']) ? trim((string) $input['client_secret']) : '';

        if (!empty($input['clear_client_secret'])) {
            $secretEnc = '';
        } elseif ($newSecret !== '') {
            $secretEnc = self::encryptSecret($newSecret);
        }

        $toSave = [
            'enabled'                => $enabled,
            'provider_name'          => $providerName,
            'client_id'              => $clientId,
            'client_secret_enc'      => $secretEnc,
            'issuer_url'             => $issuerUrl,
            'authorize_url'          => $authorizeUrl,
            'token_url'              => $tokenUrl,
            'userinfo_url'           => $userinfoUrl,
            'scopes'                 => $scopes,
            'claim_username'         => $claimUsername,
            'claim_email'            => $claimEmail,
            'match_by'               => $matchBy,
            'allow_jit_provisioning' => $allowJit,
            'timeout_seconds'        => (string) $timeout,
            'retention_days'         => (string) $retention,
        ];

        if (class_exists('Config') && method_exists('Config', 'setConfigurationValues')) {
            Config::setConfigurationValues(self::CONTEXT, $toSave);
        }

        return ['ok' => true, 'errors' => []];
    }

    /**
     * Hook callback to prevent disclosure of secret keys over REST API.
     *
     * @param array $params
     * @return array
     */
    public static function undiscloseConfigValue(array $params): array
    {
        $sensitive = ['client_secret_enc', 'secret_key'];

        if (
            isset($params['context'], $params['name'])
            && $params['context'] === self::CONTEXT
            && in_array((string) $params['name'], $sensitive, true)
        ) {
            $params['value'] = '';
        }

        if (isset($params[self::CONTEXT]) && is_array($params[self::CONTEXT])) {
            foreach ($sensitive as $field) {
                unset($params[self::CONTEXT][$field]);
            }
        }

        return $params;
    }
}

if (PluginSsologinCompat::typedRightname()) {
    class PluginSsologinConfig extends CommonGLPI implements PluginSsologinConfigConstants
    {
        use PluginSsologinConfigBody;

        public static string $rightname = 'config';
    }
} else {
    class PluginSsologinConfig extends CommonGLPI implements PluginSsologinConfigConstants
    {
        use PluginSsologinConfigBody;

        public static $rightname = 'config';
    }
}
