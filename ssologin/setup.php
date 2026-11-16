<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Inicializacao do plugin (GLPI 10 / 11 / 12)
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

define('PLUGIN_SSOLOGIN_VERSION', '1.0.0');
define('PLUGIN_SSOLOGIN_MIN_GLPI', '10.0.0');
define('PLUGIN_SSOLOGIN_MAX_GLPI', '12.0.99');

require_once __DIR__ . '/inc/compat.class.php';
require_once __DIR__ . '/inc/config.class.php';
require_once __DIR__ . '/inc/oidc.class.php';

/**
 * Initializes plugin hooks.
 */
function plugin_init_ssologin(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['ssologin'] = true;

    $cssAsset = PluginSsologinCompat::assetPath('css/ssologin.css');
    $PLUGIN_HOOKS['add_css']['ssologin']                = [$cssAsset];
    $PLUGIN_HOOKS['add_css_anonymous_page']['ssologin'] = [$cssAsset];

    $PLUGIN_HOOKS['display_login']['ssologin']         = [PluginSsologinOidc::class, 'displayLoginButton'];
    $PLUGIN_HOOKS['undiscloseConfigValue']['ssologin'] = [PluginSsologinConfig::class, 'undiscloseConfigValue'];

    if (class_exists('Session') && Session::haveRight('config', UPDATE)) {
        $PLUGIN_HOOKS['config_page']['ssologin'] = 'front/config.form.php';
    }
}

/**
 * Returns plugin metadata and compatibility ranges.
 */
function plugin_version_ssologin(): array
{
    return [
        'name'         => __('SSO Login', 'ssologin'),
        'version'      => PLUGIN_SSOLOGIN_VERSION,
        'author'       => 'G. Martins',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://github.com/GustavoMS0/GLPI-SsoLogin',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SSOLOGIN_MIN_GLPI,
                'max' => PLUGIN_SSOLOGIN_MAX_GLPI,
            ],
            'php'  => [
                'min' => '7.4',
            ],
        ],
    ];
}

/**
 * Checks GLPI and PHP prerequisites before installation.
 */
function plugin_ssologin_check_prerequisites(): bool
{
    if (version_compare(PHP_VERSION, '7.4.0', '<')) {
        echo "This plugin requires PHP >= 7.4.0.";
        return false;
    }
    if (
        defined('GLPI_VERSION')
        && (
            version_compare((string) GLPI_VERSION, PLUGIN_SSOLOGIN_MIN_GLPI, '<')
            || version_compare((string) GLPI_VERSION, PLUGIN_SSOLOGIN_MAX_GLPI, '>')
        )
    ) {
        echo "This plugin requires GLPI between " . PLUGIN_SSOLOGIN_MIN_GLPI . " and " . PLUGIN_SSOLOGIN_MAX_GLPI . ".";
        return false;
    }
    if (!extension_loaded('openssl')) {
        echo "This plugin requires the PHP openssl extension.";
        return false;
    }
    return true;
}

/**
 * Checks plugin configuration status.
 */
function plugin_ssologin_check_config($verbose = false): bool
{
    return true;
}
