<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Inicio do fluxo OAuth 2.0 / OIDC com PKCE (S256)
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

$SECURITY_STRATEGY = 'no_check';

if (!defined('GLPI_ROOT')) {
    include_once __DIR__ . '/../../../inc/includes.php';
}

require_once __DIR__ . '/../setup.php';

global $CFG_GLPI;
$loginFallback = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . '/index.php';

if (class_exists('Plugin')) {
    $plugin = new Plugin();
    if (method_exists($plugin, 'isActivated') && !$plugin->isActivated('ssologin')) {
        PluginSsologinCompat::denyAccess();
    }
}

$requestedRedirect = isset($_GET['redirect']) && is_string($_GET['redirect'])
    ? $_GET['redirect']
    : '';

$flow = PluginSsologinOidc::startAuthorizationFlow($requestedRedirect);

if (empty($flow['ok']) || empty($flow['redirect_url'])) {
    if (class_exists('Session') && method_exists('Session', 'addMessageAfterRedirect')) {
        Session::addMessageAfterRedirect(
            __('SSO Login is currently unavailable. Please sign in with your local credentials.', 'ssologin'),
            false,
            ERROR
        );
    }
    Html::redirect($loginFallback);
}

if (!headers_sent()) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

Html::redirect((string) $flow['redirect_url']);
