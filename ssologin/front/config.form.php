<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Formulario de configuracao e auditoria
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
    include_once __DIR__ . '/../../../inc/includes.php';
}

require_once __DIR__ . '/../setup.php';

if (class_exists('Plugin')) {
    $plugin = new Plugin();
    if (method_exists($plugin, 'isActivated') && !$plugin->isActivated('ssologin')) {
        PluginSsologinCompat::denyAccess();
    }
}

if (!class_exists('Session') || !Session::haveRight('config', UPDATE)) {
    PluginSsologinCompat::denyAccess();
}

$selfUrl = PluginSsologinCompat::webPath(false) . '/front/config.form.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!PluginSsologinCompat::requireSafePost()) {
        PluginSsologinCompat::denyAccess();
    }

    if (isset($_POST['purge_logs'])) {
        $cfg = PluginSsologinConfig::getConfig();
        PluginSsologinOidc::purgeOldLogs((int) ($cfg['retention_days'] ?? 90));
        if (class_exists('Session') && method_exists('Session', 'addMessageAfterRedirect')) {
            Session::addMessageAfterRedirect(__('Old SSO audit logs have been purged.', 'ssologin'), false, INFO);
        }
        Html::redirect($selfUrl);
    }

    if (isset($_POST['save_config'])) {
        $cleanInput = [
            'enabled'                => !empty($_POST['enabled']) ? '1' : '0',
            'provider_name'          => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['provider_name'] ?? '')),
            'client_id'              => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['client_id'] ?? '')),
            'client_secret'          => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['client_secret'] ?? '')),
            'clear_client_secret'    => !empty($_POST['clear_client_secret']) ? '1' : '0',
            'issuer_url'             => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['issuer_url'] ?? '')),
            'authorize_url'          => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['authorize_url'] ?? '')),
            'token_url'              => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['token_url'] ?? '')),
            'userinfo_url'           => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['userinfo_url'] ?? '')),
            'scopes'                 => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['scopes'] ?? '')),
            'claim_username'         => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['claim_username'] ?? '')),
            'claim_email'            => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['claim_email'] ?? '')),
            'match_by'               => PluginSsologinCompat::fromSanitizedInput((string) ($_POST['match_by'] ?? 'both')),
            'allow_jit_provisioning' => !empty($_POST['allow_jit_provisioning']) ? '1' : '0',
            'timeout_seconds'        => (int) ($_POST['timeout_seconds'] ?? 10),
            'retention_days'         => (int) ($_POST['retention_days'] ?? 90),
        ];

        $result = PluginSsologinConfig::saveConfig($cleanInput);
        if (!empty($result['ok'])) {
            if (class_exists('Session') && method_exists('Session', 'addMessageAfterRedirect')) {
                Session::addMessageAfterRedirect(__('SSO configuration saved successfully.', 'ssologin'), false, INFO);
            }
        } else {
            foreach ($result['errors'] as $err) {
                if (class_exists('Session') && method_exists('Session', 'addMessageAfterRedirect')) {
                    Session::addMessageAfterRedirect(
                        htmlspecialchars((string) $err, ENT_QUOTES, 'UTF-8'),
                        false,
                        ERROR
                    );
                }
            }
        }
        Html::redirect($selfUrl);
    }
}

$config          = PluginSsologinConfig::getConfig();
$hasSecret       = PluginSsologinConfig::hasClientSecret();
$callbackUrl     = PluginSsologinOidc::getCallbackUrl();
$recentLogs      = PluginSsologinOidc::getRecentLogs(50);
$secretPlaceholder = $hasSecret
    ? __('Secret configured (leave blank to keep current)', 'ssologin')
    : __('Enter OAuth2 client secret', 'ssologin');

Html::header(__('SSO Login', 'ssologin'), $selfUrl, 'config', 'plugins');

echo '<div class="ssologin-admin-wrap">';
echo '<form method="post" action="' . htmlspecialchars($selfUrl, ENT_QUOTES, 'UTF-8') . '">';
echo '<div class="card mb-4">';
echo '<div class="card-header"><h3 class="card-title m-0">' . htmlspecialchars(__('OpenID Connect / OAuth 2.0 Settings (PKCE S256)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</h3></div>';
echo '<div class="card-body">';

echo '<table class="tab_cadre_fixe">';

echo '<tr class="tab_bg_1">';
echo '<td style="width: 30%;"><label for="ssologin_enabled">' . htmlspecialchars(__('Enable SSO Login', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="checkbox" id="ssologin_enabled" name="enabled" value="1"' . (((int) $config['enabled'] === 1) ? ' checked="checked"' : '') . '></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td>' . htmlspecialchars(__('Callback / Redirect URI (Read-Only)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</td>';
echo '<td><input type="text" class="form-control" readonly="readonly" value="' . htmlspecialchars($callbackUrl, ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_provider_name">' . htmlspecialchars(__('Identity Provider Display Name', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="text" id="ssologin_provider_name" class="form-control" name="provider_name" maxlength="100" value="' . htmlspecialchars((string) $config['provider_name'], ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_client_id">' . htmlspecialchars(__('Client ID', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="text" id="ssologin_client_id" class="form-control" name="client_id" maxlength="255" value="' . htmlspecialchars((string) $config['client_id'], ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_client_secret">' . htmlspecialchars(__('Client Secret (AES-256-GCM encrypted at rest)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td>';
echo '<input type="password" id="ssologin_client_secret" class="form-control" name="client_secret" value="" autocomplete="new-password" placeholder="' . htmlspecialchars($secretPlaceholder, ENT_QUOTES, 'UTF-8') . '">';
if ($hasSecret) {
    echo '<div class="mt-1"><label><input type="checkbox" name="clear_client_secret" value="1"> ' . htmlspecialchars(__('Clear stored Client Secret', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></div>';
}
echo '</td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_issuer_url">' . htmlspecialchars(__('Issuer URL (HTTPS, optional)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="url" id="ssologin_issuer_url" class="form-control" name="issuer_url" value="' . htmlspecialchars((string) $config['issuer_url'], ENT_QUOTES, 'UTF-8') . '" placeholder="https://login.microsoftonline.com/<tenant>/v2.0"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_authorize_url">' . htmlspecialchars(__('Authorization Endpoint URL (HTTPS)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="url" id="ssologin_authorize_url" class="form-control" name="authorize_url" value="' . htmlspecialchars((string) $config['authorize_url'], ENT_QUOTES, 'UTF-8') . '" placeholder="https://idp.example.com/oauth2/v2.0/authorize"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_token_url">' . htmlspecialchars(__('Token Endpoint URL (HTTPS)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="url" id="ssologin_token_url" class="form-control" name="token_url" value="' . htmlspecialchars((string) $config['token_url'], ENT_QUOTES, 'UTF-8') . '" placeholder="https://idp.example.com/oauth2/v2.0/token"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_userinfo_url">' . htmlspecialchars(__('UserInfo Endpoint URL (HTTPS, recommended)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="url" id="ssologin_userinfo_url" class="form-control" name="userinfo_url" value="' . htmlspecialchars((string) $config['userinfo_url'], ENT_QUOTES, 'UTF-8') . '" placeholder="https://idp.example.com/oidc/userinfo"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_scopes">' . htmlspecialchars(__('OAuth2 Scopes', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="text" id="ssologin_scopes" class="form-control" name="scopes" maxlength="255" value="' . htmlspecialchars((string) $config['scopes'], ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_claim_username">' . htmlspecialchars(__('Username Claim', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="text" id="ssologin_claim_username" class="form-control" name="claim_username" maxlength="64" value="' . htmlspecialchars((string) $config['claim_username'], ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_claim_email">' . htmlspecialchars(__('Email Claim', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="text" id="ssologin_claim_email" class="form-control" name="claim_email" maxlength="64" value="' . htmlspecialchars((string) $config['claim_email'], ENT_QUOTES, 'UTF-8') . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_match_by">' . htmlspecialchars(__('User Matching Mode', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td>';
echo '<select id="ssologin_match_by" class="form-select form-control" name="match_by">';
$modes = [
    'both'     => __('Username or Verified Email (unique match)', 'ssologin'),
    'email'    => __('Verified Email only (unique match)', 'ssologin'),
    'username' => __('Username only (unique match)', 'ssologin'),
];
foreach ($modes as $mKey => $mLabel) {
    $selected = ($config['match_by'] === $mKey) ? ' selected="selected"' : '';
    echo '<option value="' . htmlspecialchars($mKey, ENT_QUOTES, 'UTF-8') . '"' . $selected . '>' . htmlspecialchars($mLabel, ENT_QUOTES, 'UTF-8') . '</option>';
}
echo '</select>';
echo '</td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_timeout">' . htmlspecialchars(__('HTTP Timeout (seconds, 3-30)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="number" id="ssologin_timeout" class="form-control" name="timeout_seconds" min="3" max="30" value="' . (int) $config['timeout_seconds'] . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_1">';
echo '<td><label for="ssologin_retention">' . htmlspecialchars(__('Audit Log Retention (days, 7-365)', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</label></td>';
echo '<td><input type="number" id="ssologin_retention" class="form-control" name="retention_days" min="7" max="365" value="' . (int) $config['retention_days'] . '"></td>';
echo '</tr>';

echo '<tr class="tab_bg_2">';
echo '<td colspan="2" class="center">';
echo '<button type="submit" name="save_config" value="1" class="btn btn-primary">' . htmlspecialchars(__('Save Configuration', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</button> ';
echo '<button type="submit" name="purge_logs" value="1" class="btn btn-outline-secondary">' . htmlspecialchars(__('Purge Old Audit Logs', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</button>';
echo '</td>';
echo '</tr>';

echo '</table>';
echo '</div></div>';
Html::closeForm();

echo '<div class="card">';
echo '<div class="card-header"><h3 class="card-title m-0">' . htmlspecialchars(__('Recent SSO Authentication Events', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</h3></div>';
echo '<div class="card-body">';
echo '<table class="tab_cadre_fixehov">';
echo '<tr>';
echo '<th>' . htmlspecialchars(__('Date', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('Event', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('Status', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('User ID', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('Identifier', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('IP Address', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '<th>' . htmlspecialchars(__('Summary', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</th>';
echo '</tr>';

if ($recentLogs === []) {
    echo '<tr class="tab_bg_1"><td colspan="7" class="center">' . htmlspecialchars(__('No SSO events recorded yet.', 'ssologin'), ENT_QUOTES, 'UTF-8') . '</td></tr>';
} else {
    foreach ($recentLogs as $log) {
        $date       = PluginSsologinCompat::fromCore((string) ($log['date_creation'] ?? ''));
        $eventType  = PluginSsologinCompat::fromCore((string) ($log['event_type'] ?? ''));
        $status     = PluginSsologinCompat::fromCore((string) ($log['status'] ?? ''));
        $uid        = (int) ($log['users_id'] ?? 0);
        $identifier = PluginSsologinCompat::fromCore((string) ($log['identifier'] ?? ''));
        $ip         = PluginSsologinCompat::fromCore((string) ($log['ip_address'] ?? ''));
        $summary    = PluginSsologinCompat::fromCore((string) ($log['summary'] ?? ''));

        echo '<tr class="tab_bg_1">';
        echo '<td>' . htmlspecialchars($date, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td><code>' . htmlspecialchars($eventType, ENT_QUOTES, 'UTF-8') . '</code></td>';
        echo '<td>' . htmlspecialchars($status, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . ($uid > 0 ? $uid : '-') . '</td>';
        echo '<td>' . htmlspecialchars($identifier, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars($summary, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '</tr>';
    }
}

echo '</table>';
echo '</div></div>';
echo '</div>';

Html::footer();
