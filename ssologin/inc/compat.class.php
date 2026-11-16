<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Camada de compatibilidade GLPI 10 / 11 / 12
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

class PluginSsologinCompat
{
    /**
     * Returns the major GLPI version (10, 11, 12...).
     */
    public static function glpiMajor(): int
    {
        $version = defined('GLPI_VERSION') ? (string) GLPI_VERSION : '10.0.0';
        if (preg_match('/^(\d+)/', $version, $matches)) {
            return (int) $matches[1];
        }
        return 10;
    }

    /**
     * Checks if running on GLPI 11.0.0-dev or higher.
     */
    public static function isGlpi11OrHigher(): bool
    {
        return defined('GLPI_VERSION')
            && version_compare((string) GLPI_VERSION, '11.0.0-dev', '>=');
    }

    /**
     * Checks if CommonGLPI::$rightname has a property type declaration (GLPI 12+).
     */
    public static function typedRightname(): bool
    {
        if (!class_exists('CommonGLPI', true)) {
            return false;
        }
        try {
            $prop = new ReflectionProperty('CommonGLPI', 'rightname');
            return $prop->hasType();
        } catch (ReflectionException $e) {
            return false;
        }
    }

    /**
     * Executes DDL statements across GLPI 10.0.0-10.0.10 (query) and 10.0.11+/11/12 (doQuery).
     *
     * @param object $db
     * @param string $sql
     * @return mixed
     */
    public static function execDdl($db, string $sql)
    {
        if (is_object($db) && method_exists($db, 'doQuery')) {
            return $db->doQuery($sql);
        }
        if (is_object($db) && method_exists($db, 'query')) {
            return $db->query($sql);
        }
        return false;
    }

    /**
     * Denies access compatibly with GLPI 10/11 (Html::displayRightError) and GLPI 12+ (AccessDeniedHttpException).
     */
    public static function denyAccess(): void
    {
        if (class_exists('Html') && method_exists('Html', 'displayRightError')) {
            Html::displayRightError();
            return;
        }
        if (class_exists('Glpi\\Exception\\Http\\AccessDeniedHttpException')) {
            throw new \Glpi\Exception\Http\AccessDeniedHttpException('Access denied');
        }
        if (!headers_sent()) {
            http_response_code(403);
        }
        if (!defined('PLUGIN_SSOLOGIN_TESTING')) {
            exit;
        }
    }

    /**
     * Base web path of the plugin, avoiding deprecated Plugin::getWebDir() on GLPI 11/12+.
     */
    public static function webPath(bool $absolute = false): string
    {
        global $CFG_GLPI;

        $isGlpi11Plus = self::isGlpi11OrHigher();

        if (
            !$isGlpi11Plus
            && class_exists('Plugin')
            && method_exists('Plugin', 'getWebDir')
        ) {
            $dir = (string) Plugin::getWebDir('ssologin', true, $absolute);
            if ($dir !== '') {
                return rtrim($dir, '/');
            }
        }

        $base = $absolute
            ? (string) ($CFG_GLPI['url_base'] ?? '')
            : (string) ($CFG_GLPI['root_doc'] ?? '');
        $base = rtrim($base, '/');

        if ($isGlpi11Plus) {
            return $base . '/plugins/ssologin';
        }

        $parentDir = basename(dirname(__DIR__, 2));
        $folder    = ($parentDir === 'marketplace') ? 'marketplace' : 'plugins';

        return $base . '/' . $folder . '/ssologin';
    }

    /**
     * Relative asset path for CSS/JS registration.
     * GLPI < 11.0.0-dev requires 'public/' prefix; GLPI >= 11.0.0-dev serves from public/.
     */
    public static function assetPath(string $relative): string
    {
        $clean = ltrim($relative, '/');
        if (strpos($clean, 'public/') === 0) {
            $clean = substr($clean, 7);
        }

        $prefix = self::isGlpi11OrHigher() ? '' : 'public/';

        return $prefix . $clean;
    }

    /**
     * Decodes HTML entities stored by core on GLPI < 11.0.0-dev without stripping literal backslashes.
     */
    public static function fromCore(?string $val): string
    {
        $value = (string) ($val ?? '');
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('Glpi\\Toolbox\\Sanitizer')
                && method_exists('Glpi\\Toolbox\\Sanitizer', 'decodeHtmlSpecialChars')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::decodeHtmlSpecialChars($value);
            }
            return htmlspecialchars_decode($value, ENT_QUOTES);
        }
        return $value;
    }

    /**
     * Unescapes superglobal $_POST/$_GET values sanitized by GLPI < 11.0.0-dev.
     */
    public static function fromSanitizedInput(?string $val): string
    {
        $value = (string) ($val ?? '');
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('Glpi\\Toolbox\\Sanitizer')
                && method_exists('Glpi\\Toolbox\\Sanitizer', 'unsanitize')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::unsanitize($value);
            }
            return htmlspecialchars_decode(stripslashes($value), ENT_QUOTES);
        }
        return $value;
    }

    /**
     * Escapes strings for $DB->insert() and $DB->update() on GLPI < 11.0.0-dev.
     */
    public static function dbValues(array $data): array
    {
        global $DB;

        if (
            !self::isGlpi11OrHigher()
            && isset($DB)
            && is_object($DB)
            && method_exists($DB, 'escape')
        ) {
            foreach ($data as $key => $val) {
                if (is_string($val)) {
                    $data[$key] = $DB->escape($val);
                }
            }
        }

        return $data;
    }

    /**
     * Prepares values for CommonDBTM::add/update on GLPI < 11.0.0-dev.
     *
     * @param mixed $values
     * @return mixed
     */
    public static function coreInput($values)
    {
        if (!self::isGlpi11OrHigher()) {
            if (class_exists('Glpi\\Toolbox\\Sanitizer')) {
                return \Glpi\Toolbox\Sanitizer::sanitize($values);
            }
            if (class_exists('Toolbox') && method_exists('Toolbox', 'addslashes_deep')) {
                return Toolbox::addslashes_deep($values);
            }
        }
        return $values;
    }

    /**
     * Validates POST method and same-origin headers without duplicating Session::checkCSRF().
     */
    public static function requireSafePost(): bool
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            if (!headers_sent()) {
                http_response_code(405);
            }
            return false;
        }

        $fetchSite = strtolower(trim((string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($fetchSite !== '') {
            $valid = ($fetchSite === 'same-origin');
        } else {
            $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
            $host   = (string) ($_SERVER['HTTP_HOST'] ?? '');

            if ($origin === '' && isset($_SERVER['HTTP_REFERER'])) {
                $origin = (string) $_SERVER['HTTP_REFERER'];
            }

            $originHost   = parse_url($origin, PHP_URL_HOST);
            $originPort   = parse_url($origin, PHP_URL_PORT);
            $expectedHost = is_string($originHost)
                ? $originHost . ($originPort !== null ? ':' . $originPort : '')
                : '';

            $valid = $origin !== ''
                && $host !== ''
                && hash_equals(strtolower($host), strtolower($expectedHost));
        }

        if (!$valid) {
            if (!headers_sent()) {
                http_response_code(403);
            }
            return false;
        }

        return true;
    }
}
