<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Rotinas de instalacao e desinstalacao
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

require_once __DIR__ . '/inc/compat.class.php';
require_once __DIR__ . '/inc/config.class.php';
require_once __DIR__ . '/inc/oidc.class.php';

/**
 * Installs database tables and default configuration for ssologin.
 */
function plugin_ssologin_install(): bool
{
    global $DB;

    if (!isset($DB) || !is_object($DB)) {
        return false;
    }

    if (!$DB->tableExists('glpi_plugin_ssologin_logs')) {
        $sql = "CREATE TABLE `glpi_plugin_ssologin_logs` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `event_type` varchar(64) NOT NULL DEFAULT '',
            `status` varchar(16) NOT NULL DEFAULT 'info',
            `users_id` int unsigned NOT NULL DEFAULT 0,
            `identifier` varchar(191) NOT NULL DEFAULT '',
            `ip_address` varchar(64) NOT NULL DEFAULT '',
            `summary` varchar(500) NOT NULL DEFAULT '',
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `idx_event_type` (`event_type`),
            KEY `idx_users_id` (`users_id`),
            KEY `idx_date_creation` (`date_creation`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        PluginSsologinCompat::execDdl($DB, $sql);
    }

    if (class_exists('Config') && method_exists('Config', 'getConfigurationValues')) {
        $existing = Config::getConfigurationValues(PluginSsologinConfig::CONTEXT);
        $defaults = PluginSsologinConfig::defaults();
        $toSet    = [];

        foreach ($defaults as $key => $val) {
            if (!is_array($existing) || !array_key_exists($key, $existing)) {
                $toSet[$key] = $val;
            }
        }

        if (!isset($existing['secret_key']) || strlen((string) $existing['secret_key']) !== 64) {
            $toSet['secret_key'] = bin2hex(random_bytes(32));
        }

        if ($toSet !== [] && method_exists('Config', 'setConfigurationValues')) {
            Config::setConfigurationValues(PluginSsologinConfig::CONTEXT, $toSet);
        }
    }

    return true;
}

/**
 * Uninstalls database tables and configuration for ssologin.
 */
function plugin_ssologin_uninstall(): bool
{
    global $DB;

    if (isset($DB) && is_object($DB)) {
        if ($DB->tableExists('glpi_plugin_ssologin_logs')) {
            PluginSsologinCompat::execDdl($DB, "DROP TABLE IF EXISTS `glpi_plugin_ssologin_logs`");
        }

        if ($DB->tableExists('glpi_configs')) {
            $DB->delete('glpi_configs', [
                'context' => PluginSsologinConfig::CONTEXT,
            ]);
        }
    }

    return true;
}
