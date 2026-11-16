<?php

/**
 * ------------------------------------------------------------------------
 * SSO Login - Bootstrap de testes unitarios (GLPI 10 / 11 / 12)
 *
 * Copyright (C) 2026 by G. Martins
 * Licensed under GPLv3+
 * ------------------------------------------------------------------------
 */

namespace {
define('PLUGIN_SSOLOGIN_TESTING', true);

if (!defined('GLPI_ROOT')) {
    define('GLPI_ROOT', dirname(__DIR__, 2));
}

$simVersion = getenv('TEST_GLPI_VERSION');
if (!is_string($simVersion) || $simVersion === '') {
    $simVersion = '11.0.0';
}
if (!defined('GLPI_VERSION')) {
    define('GLPI_VERSION', $simVersion);
}

if (!defined('UPDATE')) {
    define('UPDATE', 2);
}
if (!defined('READ')) {
    define('READ', 1);
}
if (!defined('INFO')) {
    define('INFO', 0);
}
if (!defined('ERROR')) {
    define('ERROR', 1);
}
if (!defined('GLPIKEY')) {
    define('GLPIKEY', 'test-glpi-installation-key-2026');
}

if (!function_exists('__')) {
    function __(string $str, string $domain = 'glpi'): string
    {
        return $str;
    }
}

$typedRightname = getenv('TEST_GLPI_TYPED_RIGHTNAME') === '1'
    || version_compare((string) GLPI_VERSION, '12.0.0-dev', '>=');

if (!class_exists('CommonGLPI')) {
    if ($typedRightname && version_compare(PHP_VERSION, '7.4.0', '>=')) {
        eval('
            class CommonGLPI {
                public static string $rightname = "";
            }
        ');
    } else {
        eval('
            class CommonGLPI {
                public static $rightname = "";
            }
        ');
    }
}

if (!class_exists('CommonDBTM')) {
    class CommonDBTM extends CommonGLPI
    {
        public $fields = [];

        public function getFromDB($id): bool
        {
            global $DB;
            $table = static::getTable();
            foreach (
                $DB->request([
                    'FROM'  => $table,
                    'WHERE' => ['id' => (int) $id],
                    'LIMIT' => 1,
                ]) as $row
            ) {
                $this->fields = $row;
                return true;
            }
            return false;
        }

        public static function getTable(): string
        {
            return '';
        }
    }
}

if (!class_exists('User')) {
    class User extends CommonDBTM
    {
        public static function getTable(): string
        {
            return 'glpi_users';
        }
    }
}

if (!class_exists('Auth')) {
    class Auth
    {
        public $user         = null;
        public $auth_succeded = false;
        public $extauth      = 0;
        public $user_present = 0;
    }
}

if (!class_exists('Session')) {
    class Session
    {
        public static $rightMap       = ['config' => UPDATE];
        public static $initializedAuth = null;
        public static $messages       = [];

        public static function haveRight(string $module, int $right): bool
        {
            $current = self::$rightMap[$module] ?? 0;
            return ($current & $right) === $right;
        }

        public static function init($auth): void
        {
            self::$initializedAuth = $auth;
        }

        public static function addMessageAfterRedirect(string $msg, bool $check = false, int $type = INFO): void
        {
            self::$messages[] = ['msg' => $msg, 'type' => $type];
        }
    }
}

if (!class_exists('Config')) {
    class Config
    {
        public static $store = [];

        public static function getConfigurationValues(string $context, array $keys = []): array
        {
            $ctx = self::$store[$context] ?? [];
            if ($keys === []) {
                return $ctx;
            }
            $out = [];
            foreach ($keys as $k) {
                if (array_key_exists($k, $ctx)) {
                    $out[$k] = $ctx[$k];
                }
            }
            return $out;
        }

        public static function setConfigurationValues(string $context, array $values): void
        {
            if (!isset(self::$store[$context])) {
                self::$store[$context] = [];
            }
            foreach ($values as $k => $v) {
                self::$store[$context][$k] = (string) $v;
            }
        }
    }
}

if (!class_exists('Plugin')) {
    class Plugin
    {
        public static $activePlugins = ['ssologin' => true];

        public function isActivated(string $key): bool
        {
            return !empty(self::$activePlugins[$key]);
        }

        public static function getWebDir(string $key, bool $full = true, bool $useUrlBase = false): string
        {
            global $CFG_GLPI;
            $base = $useUrlBase
                ? (string) ($CFG_GLPI['url_base'] ?? '')
                : (string) ($CFG_GLPI['root_doc'] ?? '');
            return rtrim($base, '/') . '/plugins/' . $key;
        }
    }
}

if (!class_exists('Html')) {
    class Html
    {
        public static $lastRedirect  = '';
        public static $rightErrorHit = false;

        public static function displayRightError(): void
        {
            self::$rightErrorHit = true;
        }

        public static function redirect(string $url): void
        {
            self::$lastRedirect = $url;
        }

        public static function header(string $title, string $url = '', string $sector = '', string $item = ''): void
        {
        }

        public static function footer(): void
        {
        }

        public static function closeForm(): void
        {
            echo '</form>';
        }
    }
}
}

namespace Glpi\Toolbox {
    if (!class_exists('Glpi\\Toolbox\\Sanitizer')) {
        class Sanitizer
        {
            public static function sanitize($val)
            {
                if (is_array($val)) {
                    $out = [];
                    foreach ($val as $k => $v) {
                        $out[$k] = self::sanitize($v);
                    }
                    return $out;
                }
                if (is_string($val)) {
                    return addslashes(htmlspecialchars($val, ENT_QUOTES, 'UTF-8'));
                }
                return $val;
            }

            public static function unsanitize($val)
            {
                if (is_string($val)) {
                    return htmlspecialchars_decode(stripslashes($val), ENT_QUOTES);
                }
                return $val;
            }

            public static function decodeHtmlSpecialChars($val)
            {
                if (is_string($val)) {
                    return htmlspecialchars_decode($val, ENT_QUOTES);
                }
                return $val;
            }
        }
    }
}

namespace Glpi\Exception\Http {
    if (!class_exists('Glpi\\Exception\\Http\\AccessDeniedHttpException')) {
        class AccessDeniedHttpException extends \RuntimeException
        {
        }
    }
}

namespace {
    class FakeTestDB
    {
        public $tables  = [];
        public $autoInc = [];
        public $ddlLog  = [];

        public function __construct()
        {
            $this->tables['glpi_users']          = [];
            $this->tables['glpi_useremails']     = [];
            $this->tables['glpi_profiles_users'] = [];
            $this->tables['glpi_configs']        = [];
        }

        public function tableExists(string $table): bool
        {
            return array_key_exists($table, $this->tables);
        }

        public function doQuery(string $sql): bool
        {
            return $this->handleDdl($sql);
        }

        public function query(string $sql): bool
        {
            return $this->handleDdl($sql);
        }

        protected function handleDdl(string $sql): bool
        {
            $this->ddlLog[] = $sql;
            if (preg_match('/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $t = $m[1];
                if (!isset($this->tables[$t])) {
                    $this->tables[$t]  = [];
                    $this->autoInc[$t] = 1;
                }
                return true;
            }
            if (preg_match('/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                unset($this->tables[$m[1]], $this->autoInc[$m[1]]);
                return true;
            }
            return true;
        }

        public function escape(string $val): string
        {
            return addslashes($val);
        }

        public function insert(string $table, array $row): int
        {
            if (!isset($this->tables[$table])) {
                $this->tables[$table] = [];
            }
            if (!isset($this->autoInc[$table])) {
                $this->autoInc[$table] = 1;
            }
            if (!isset($row['id'])) {
                $row['id'] = $this->autoInc[$table]++;
            } else {
                $this->autoInc[$table] = max($this->autoInc[$table], ((int) $row['id']) + 1);
            }
            $this->tables[$table][] = $row;
            return (int) $row['id'];
        }

        public function update(string $table, array $changes, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }
            foreach ($this->tables[$table] as $idx => $row) {
                if ($this->matchesWhere($row, $where)) {
                    foreach ($changes as $k => $v) {
                        $this->tables[$table][$idx][$k] = $v;
                    }
                }
            }
            return true;
        }

        public function delete(string $table, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }
            $remaining = [];
            foreach ($this->tables[$table] as $row) {
                if (!$this->matchesWhere($row, $where)) {
                    $remaining[] = $row;
                }
            }
            $this->tables[$table] = $remaining;
            return true;
        }

        public function request(array $crit): array
        {
            $from = (string) ($crit['FROM'] ?? '');
            $rows = $this->tables[$from] ?? [];
            $where = $crit['WHERE'] ?? [];

            $filtered = [];
            foreach ($rows as $row) {
                if ($this->matchesWhere($row, $where)) {
                    $filtered[] = $row;
                }
            }

            if (isset($crit['ORDER']) && is_string($crit['ORDER'])) {
                if (stripos($crit['ORDER'], 'id DESC') !== false) {
                    usort($filtered, function (array $a, array $b): int {
                        return ((int) ($b['id'] ?? 0)) <=> ((int) ($a['id'] ?? 0));
                    });
                }
            }

            if (isset($crit['LIMIT'])) {
                $filtered = array_slice($filtered, 0, (int) $crit['LIMIT']);
            }

            return $filtered;
        }

        protected function matchesWhere(array $row, array $where): bool
        {
            foreach ($where as $col => $expected) {
                $actual = $row[$col] ?? null;
                if (is_array($expected) && count($expected) === 2 && $expected[0] === '<') {
                    if ((string) $actual >= (string) $expected[1]) {
                        return false;
                    }
                } elseif ((string) $actual !== (string) $expected) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * Simulates GLPI 10.0.0-10.0.10 DBmysql which only has query() and NOT doQuery().
     */
    class LegacyQueryOnlyDB
    {
        public $tables = [];
        public $ddlLog = [];

        public function tableExists(string $table): bool
        {
            return array_key_exists($table, $this->tables);
        }

        public function query(string $sql): bool
        {
            $this->ddlLog[] = $sql;
            if (preg_match('/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $this->tables[$m[1]] = [];
                return true;
            }
            if (preg_match('/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                unset($this->tables[$m[1]]);
                return true;
            }
            return true;
        }

        public function delete(string $table, array $where): bool
        {
            return true;
        }
    }

    global $DB, $CFG_GLPI, $PLUGIN_HOOKS;
    $DB           = new FakeTestDB();
    $CFG_GLPI     = [
        'root_doc' => '/glpi',
        'url_base' => 'https://glpi.example.org/glpi',
    ];
    $PLUGIN_HOOKS = [];

    require_once dirname(__DIR__) . '/ssologin/setup.php';
    require_once dirname(__DIR__) . '/ssologin/hook.php';
}
