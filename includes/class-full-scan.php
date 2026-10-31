<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Full_Scan {

    const RESULT_OPT    = 'swps_full_scan_result';
    const HISTORY_OPT   = 'swps_full_scan_history';
    const SKIPPED_OPT   = 'swps_full_scan_skipped';
    const WHITELIST_OPT = 'swps_full_scan_whitelist';

    public static function init() {
        // AJAX handlers
        add_action('wp_ajax_swps_full_scan_run',       array(__CLASS__, 'ajax_run_step'));
        add_action('wp_ajax_swps_full_scan_fix',       array(__CLASS__, 'ajax_fix'));
        add_action('wp_ajax_swps_full_scan_fix_all',   array(__CLASS__, 'ajax_fix_all'));
        add_action('wp_ajax_swps_full_scan_skip',      array(__CLASS__, 'ajax_skip'));
        add_action('wp_ajax_swps_full_scan_unskip',    array(__CLASS__, 'ajax_unskip'));
        add_action('wp_ajax_swps_full_scan_whitelist', array(__CLASS__, 'ajax_whitelist'));
        add_action('wp_ajax_swps_full_scan_clear',     array(__CLASS__, 'ajax_clear'));
        add_action('wp_ajax_swps_full_scan_report',    array(__CLASS__, 'ajax_export_report'));
        add_action('wp_ajax_swps_full_scan_email',     array(__CLASS__, 'ajax_email_report'));
        add_action('wp_ajax_swps_full_scan_history',   array(__CLASS__, 'ajax_get_history'));

        // Scheduled auto-scan
        add_action('swps_scheduled_full_scan', array(__CLASS__, 'run_scheduled_scan'));
        add_filter('cron_schedules',           array(__CLASS__, 'add_cron_schedule'));

        // Schedule setup on settings change
        add_action('update_option_swps_settings', array(__CLASS__, 'maybe_reschedule'), 10, 2);
    }

    /* ─────────────────────────────────────────────
     * SCAN STEPS DEFINITION
     * ───────────────────────────────────────────── */
    public static function get_steps() {
        return array(
            'malware'     => array('label' => 'Malware Scanner',        'icon' => '🦠', 'category' => 'files'),
            'dna'         => array('label' => 'DNA Signature Scan',     'icon' => '🧬', 'category' => 'files'),
            'core'        => array('label' => 'Core File Integrity',    'icon' => '🔧', 'category' => 'files'),
            'fim'         => array('label' => 'File Change Monitor',    'icon' => '📁', 'category' => 'files'),
            'vuln'        => array('label' => 'Plugin/Theme Vulns',     'icon' => '🔍', 'category' => 'software'),
            'ssl'         => array('label' => 'SSL Certificate',        'icon' => '🔒', 'category' => 'network'),
            'blacklist'   => array('label' => 'Blacklist Check',        'icon' => '📋', 'category' => 'network'),
            'users'       => array('label' => 'Suspicious Users',       'icon' => '👤', 'category' => 'access'),
            'headers'     => array('label' => 'Security Headers',       'icon' => '🛡️', 'category' => 'hardening'),
            'permissions' => array('label' => 'File Permissions',       'icon' => '🔑', 'category' => 'hardening'),
            'risky_files' => array('label' => 'Exposed Backup/Log Files','icon' => '🗂️', 'category' => 'files'),
        );
    }

    /* ─────────────────────────────────────────────
     * SECURITY SCORE CALCULATION
     * ───────────────────────────────────────────── */
    public static function calculate_score($results = null, $skipped = null, $whitelist = null) {
        if (!$results)   $results   = get_option(self::RESULT_OPT, array());
        if (!$skipped)   $skipped   = get_option(self::SKIPPED_OPT, array());
        if (!$whitelist) $whitelist = get_option(self::WHITELIST_OPT, array());

        $score       = 100;
        $deductions  = array();

        // Score deduction weights
        $weights = array(
            'critical' => 15,
            'warning'  => 5,
            'info'     => 1,
        );

        // Fix: deductions used to be unbounded per step, so any single scan
        // step that happens to produce a lot of individually-minor findings
        // (classically: a legitimate theme/plugin install adding 50-100+
        // files, each only an 'info'-severity "new file" notice since the
        // v5.0.18 severity fix) could still add up to tank the WHOLE site's
        // grade to F on its own — confirmed live BEFORE that severity fix
        // (90 added-file warnings at 5pts each = -450, floored to 0/F).
        // Capping how much any one step can drag the score down means a
        // single noisy-but-low-risk category can no longer dominate the
        // overall grade; a site with real critical issues elsewhere still
        // scores accordingly since those use their own, uncapped pool.
        $step_cap = 25;

        foreach ($results as $step => $data) {
            $step_deduction = 0;
            foreach ($data['issues'] ?? array() as $issue) {
                if (in_array($issue['id'], $skipped))   continue;
                if (in_array($issue['id'], $whitelist)) continue;

                $weight = $weights[$issue['severity']] ?? 3;
                if ($issue['severity'] !== 'critical' && $step_deduction >= $step_cap) continue; // capped — still listed as an issue, just stops costing score
                $step_deduction += $weight;
                $score -= $weight;
                $deductions[] = array(
                    'issue'   => $issue['title'],
                    'sev'     => $issue['severity'],
                    'points'  => $weight,
                );
            }
        }

        $score = max(0, min(100, $score));

        $grade = 'A+';
        if ($score < 90) $grade = 'A';
        if ($score < 80) $grade = 'B';
        if ($score < 70) $grade = 'C';
        if ($score < 50) $grade = 'D';
        if ($score < 30) $grade = 'F';

        $color = '#2ecc71';
        if ($score < 80) $color = '#f39c12';
        if ($score < 50) $color = '#e74c3c';

        return array(
            'score'      => $score,
            'grade'      => $grade,
            'color'      => $color,
            'deductions' => $deductions,
        );
    }

    /* ─────────────────────────────────────────────
     * RUN A SINGLE STEP
     * ───────────────────────────────────────────── */
    public static function run_step($step) {
        $issues   = array();
        $whitelist= get_option(self::WHITELIST_OPT, array());

        switch ($step) {

            case 'malware':
                $result = SWPS_Scanner::run_scan();
                foreach ($result['threats'] ?? array() as $file) {
                    $path = $file['file'] ?? '';
                    if (!$path) continue;
                    $id = 'malware_' . md5($path);
                    if (in_array($id, $whitelist)) continue;
                    $issues[] = self::make_issue($id, 'critical',
                        'Malware: ' . basename($path),
                        $path . ' — ' . implode(', ', (array)($file['threats'] ?? array())),
                        'quarantine', 'Quarantine File',
                        array('file' => $path)
                    );
                }
                break;

            case 'dna':
                $result = SWPS_Malware_DNA::run_scan();
                foreach ($result['results'] ?? array() as $r) {
                    $id      = 'dna_' . md5($r['file']);
                    if (in_array($id, $whitelist)) continue;
                    $sig_ids = implode(', ', array_column($r['findings'], 'sig_id'));
                    $issues[] = self::make_issue($id,
                        $r['critical'] ? 'critical' : 'warning',
                        'DNA Match: ' . basename($r['file']),
                        $r['file'] . ' [' . $sig_ids . ']',
                        'quarantine_rel', 'Quarantine',
                        array('file' => $r['file'])
                    );
                }
                break;

            case 'core':
                $result = SWPS_Core_Repair::verify();
                foreach ($result['modified'] ?? array() as $item) {
                    $id = 'core_mod_' . md5($item['file']);
                    if (in_array($id, $whitelist)) continue;
                    $issues[] = self::make_issue($id, 'critical',
                        'Core modified: ' . $item['file'],
                        'Hash mismatch — file was changed after WordPress install.',
                        'repair_core', 'Repair from WP.org',
                        array('file' => $item['file'])
                    );
                }
                // Fix: WordPress core now bundles large third-party library
                // directories under wp-includes/ (e.g. php-ai-client, added
                // in recent WP releases — 146 files in its own right). When
                // a whole such bundle is unreadable to PHP (a common cause
                // on shared/managed hosts: open_basedir or a lean/custom
                // core install that strips unused bundled libraries) this
                // used to report 20-30+ separate "critical" issues — one
                // per file — crashing the score to an alarming Grade F over
                // what is very often a single host-level quirk, not file-by-
                // file tampering. Missing files are now grouped by their
                // wp-includes/<library>/ root; a library with several
                // missing files becomes ONE issue (and a WARNING, not
                // critical — a dormant bundled library being absent is a
                // much lower real risk than a tampered load-bearing file),
                // while an isolated missing file elsewhere stays critical,
                // since that pattern really does suggest tampering/deletion.
                $missing_groups = array();
                foreach ($result['missing'] ?? array() as $file) {
                    $lib = null;
                    if (preg_match('#^wp-includes/([^/]+)/#', $file, $m)) $lib = 'wp-includes/' . $m[1];
                    $key = $lib ?: $file;
                    $missing_groups[$key][] = $file;
                }
                foreach ($missing_groups as $key => $files) {
                    if (count($files) >= 4 && strpos($key, '/') !== false) {
                        $id = 'core_miss_lib_' . md5($key);
                        if (in_array($id, $whitelist)) continue;
                        $issues[] = self::make_issue($id, 'warning',
                            'Bundled library incomplete: ' . $key . ' (' . count($files) . ' files)',
                            'Several files under this WordPress-bundled library are unreadable or missing — often caused by a host restricting which files PHP can see (open_basedir), or a lean/custom core install, rather than tampering. Still worth restoring to be sure.',
                            'repair_core_bundle', 'Restore all ' . count($files) . ' files',
                            array('prefix' => $key)
                        );
                        continue;
                    }
                    foreach ($files as $file) {
                        $id = 'core_miss_' . md5($file);
                        if (in_array($id, $whitelist)) continue;
                        $issues[] = self::make_issue($id, 'critical',
                            'Core missing: ' . $file,
                            'This WordPress core file does not exist.',
                            'repair_core', 'Restore from WP.org',
                            array('file' => $file)
                        );
                    }
                }
                break;

            case 'fim':
                $stats = SWPS_File_Integrity::get_stats();
                foreach ($stats['changes'] ?? array() as $change) {
                    $id = 'fim_' . md5($change['file']);
                    if (in_array($id, $whitelist)) continue;

                    // Fix: a MODIFIED (not new, not deleted) plugin/theme
                    // file used to only offer "Quarantine" — moving it aside
                    // fixes the infection but also breaks the plugin/theme
                    // until someone manually reinstalls it. If the plugin or
                    // theme is actually hosted on WordPress.org, we can
                    // instead pull the official file for the exact installed
                    // version and restore it in place — the same idea as
                    // Core Repair, just extended past wp-admin/wp-includes.
                    // Matches the research finding that this is exactly what
                    // Wordfence/Sucuri/Solid do too, and exactly where they
                    // ALSO stop: a premium/commercial plugin or theme has no
                    // public official copy to restore from, so it still only
                    // gets Quarantine — same honest limit as every
                    // competitor, not a gap unique to us.
                    $fix_type  = 'quarantine_rel';
                    $fix_label = 'Quarantine';
                    if ($change['type'] === 'modified') {
                        if (preg_match('#^wp-content/plugins/([^/]+)/#', $change['file'], $m)
                            && class_exists('SWPS_Plugin_Theme_Repair') && SWPS_Plugin_Theme_Repair::is_wporg_plugin($m[1])) {
                            $fix_type = 'repair_plugin_file'; $fix_label = 'Repair from WP.org';
                        } elseif (preg_match('#^wp-content/themes/([^/]+)/#', $change['file'], $m)
                            && class_exists('SWPS_Plugin_Theme_Repair') && SWPS_Plugin_Theme_Repair::is_wporg_theme($m[1])) {
                            $fix_type = 'repair_theme_file'; $fix_label = 'Repair from WP.org';
                        }
                    }

                    $issues[] = self::make_issue($id, $change['severity'],
                        strtoupper($change['type']) . ': ' . basename($change['file']),
                        $change['file'],
                        $fix_type, $fix_label,
                        array('file' => $change['file'])
                    );
                }
                break;

            case 'vuln':
                // Run an actual (cache-aware) scan instead of trusting a
                // possibly-stale or never-populated cached option — otherwise
                // a site that hasn't hit its daily cron yet always reports
                // "Clean" without ever having scanned anything.
                $result = class_exists('SWPS_Vuln_Scanner')
                    ? SWPS_Vuln_Scanner::run_scan()
                    : get_option('swps_last_vuln_scan', array());

                // Flatten: WordPress core + each plugin + each theme.
                $groups = array();
                if (!empty($result['wordpress']['vulnerabilities'])) {
                    $groups[] = array('slug' => 'wordpress', 'label' => 'WordPress Core', 'type' => 'core',
                        'vulns' => $result['wordpress']['vulnerabilities']);
                }
                foreach (array('plugins' => 'plugin', 'themes' => 'theme') as $gkey => $gtype) {
                    foreach ((array)($result[$gkey] ?? array()) as $item) {
                        if (empty($item['vulnerabilities'])) continue;
                        $groups[] = array('slug' => $item['slug'] ?? '', 'label' => $item['name'] ?? ($item['slug'] ?? ''),
                            'type' => $gtype, 'vulns' => $item['vulnerabilities']);
                    }
                }

                foreach ($groups as $g) {
                    foreach ($g['vulns'] as $vuln) {
                        $id = 'vuln_' . md5($g['slug'] . ($vuln['title'] ?? '') . ($vuln['cve'] ?? ''));
                        if (in_array($id, $whitelist)) continue;
                        $cvss = $vuln['cvss_score'] ?? null;
                        $sev  = ($cvss !== null && $cvss >= 7) ? 'critical' : 'warning';
                        $fix  = (!empty($vuln['fixed_in']) && $g['type'] === 'plugin') ? 'update_plugin' : 'none';
                        $issues[] = self::make_issue($id, $sev,
                            $g['label'] . ': ' . ($vuln['title'] ?? 'Vulnerability found'),
                            (!empty($vuln['fixed_in']) ? 'Fixed in v' . $vuln['fixed_in'] : 'No fix available yet')
                                . ($vuln['cve'] ? ' — ' . (is_array($vuln['cve']) ? implode(', ', $vuln['cve']) : $vuln['cve']) : ''),
                            $fix, 'Update Now',
                            array('slug' => $g['slug'])
                        );
                    }
                }
                break;

            case 'ssl':
                $host = parse_url(get_site_url(), PHP_URL_HOST);
                $ssl  = SWPS_SSL_Monitor::get_ssl_info($host);
                if (!$ssl || !empty($ssl['error'])) {
                    $id = 'ssl_error';
                    if (!in_array($id, $whitelist))
                        $issues[] = self::make_issue($id, 'critical', 'SSL check failed', $ssl['error']??'', 'none', '', array());
                } elseif (($ssl['days_remaining']??999) <= 0) {
                    $id = 'ssl_expired';
                    if (!in_array($id, $whitelist))
                        $issues[] = self::make_issue($id, 'critical', 'SSL EXPIRED', 'Expired: '.($ssl['valid_to']??''), 'none', 'Renew SSL', array());
                } elseif (($ssl['days_remaining']??999) <= 14) {
                    $id = 'ssl_expiring';
                    if (!in_array($id, $whitelist))
                        $issues[] = self::make_issue($id, 'warning', 'SSL expires in '.$ssl['days_remaining'].' days', 'Valid to: '.($ssl['valid_to']??''), 'none', 'Renew SSL', array());
                }
                break;

            case 'blacklist':
                // Run the check (uses its own 6h cache) so the current logic is
                // applied, rather than reading a possibly-stale stored result.
                $bl = class_exists('SWPS_Blacklist_Monitor')
                    ? SWPS_Blacklist_Monitor::check()
                    : get_option('swps_blacklist_last_check', array());
                foreach ($bl as $key => $data) {
                    if (!is_array($data) || empty($data['listed'])) continue;
                    $id = 'bl_' . $key;
                    if (in_array($id, $whitelist)) continue;
                    $issues[] = self::make_issue($id, 'critical',
                        'Blacklisted: ' . ($data['name'] ?? $key),
                        $data['note'] ?? 'Submit removal request.',
                        'none', 'View Delisting', array()
                    );
                }
                break;

            case 'users':
                $admins    = get_users(array('role' => 'administrator'));
                $known_ids = (array)get_option('swps_known_admin_ids', array(1));
                foreach ($admins as $user) {
                    if (in_array($user->ID, $known_ids)) continue;
                    $id = 'user_' . $user->ID;
                    if (in_array($id, $whitelist)) continue;
                    $issues[] = self::make_issue($id, 'critical',
                        'Unknown admin: ' . $user->user_login,
                        'ID:'.$user->ID.' | Email:'.$user->user_email.' | Registered:'.$user->user_registered,
                        'delete_user', 'Delete User',
                        array('user_id' => $user->ID, 'login' => $user->user_login)
                    );
                }
                break;

            case 'headers':
                if (!class_exists('SWPS_Security_Headers')) break;
                $test = SWPS_Security_Headers::test_headers();
                foreach ($test as $data) {
                    if (!empty($data['present'])) continue;
                    $name = $data['header'] ?? '';
                    if (!$name) continue;
                    $id = 'hdr_' . md5($name);
                    if (in_array($id, $whitelist)) continue;
                    $issues[] = self::make_issue($id, 'warning',
                        'Missing header: ' . $name,
                        'This security header is not being sent by your site.',
                        'enable_headers', 'Enable Headers', array()
                    );
                }
                break;

            case 'permissions':
                $checks = array(
                    ABSPATH . 'wp-config.php'  => '0400',
                    ABSPATH . '.htaccess'       => '0644',
                    WP_CONTENT_DIR . '/uploads' => '0755',
                );
                foreach ($checks as $path => $recommended) {
                    if (!file_exists($path)) continue;
                    $actual = substr(sprintf('%o', fileperms($path)), -4);
                    $risky  = ($actual === '0777' || $actual === '0666' ||
                               (strpos($path,'wp-config') !== false && !in_array($actual, array('0400','0440','0600','0640'))));
                    if (!$risky) continue;
                    $id = 'perm_' . md5($path);
                    if (in_array($id, $whitelist)) continue;
                    $sev = strpos($path,'wp-config') !== false ? 'critical' : 'warning';
                    $issues[] = self::make_issue($id, $sev,
                        'Unsafe permissions: ' . basename($path),
                        "Current: $actual — Recommended: $recommended",
                        'fix_permissions', 'Fix Now',
                        array('path' => $path, 'mode' => $recommended)
                    );
                }
                break;

            case 'risky_files':
                foreach ( SWPS_File_Integrity::scan_risky_files() as $rel ) {
                    $id = 'risky_' . md5($rel);
                    if (in_array($id, $whitelist)) continue;
                    $critical = (stripos($rel, 'wp-config') !== false || stripos($rel, 'debug.log') === 0 || stripos($rel, '/debug.log') !== false);
                    $issues[] = self::make_issue($id, $critical ? 'critical' : 'warning',
                        'Exposed file: ' . basename($rel),
                        $rel . ' — not part of WordPress core/plugin/theme files and publicly downloadable over HTTP (may contain credentials, secrets, or server paths).',
                        'quarantine_rel', 'Quarantine',
                        array('file' => $rel)
                    );
                }
                break;
        }

        return $issues;
    }

    /* ─────────────────────────────────────────────
     * ISSUE FACTORY
     * ───────────────────────────────────────────── */
    private static function make_issue($id, $severity, $title, $detail, $fix, $fix_label, $fix_data) {
        return array(
            'id'        => $id,
            'severity'  => $severity,
            'title'     => $title,
            'detail'    => $detail,
            'fix'       => $fix,
            'fix_label' => $fix_label,
            'fix_data'  => $fix_data,
            'fixed'     => false,
            'found_at'  => time(),
        );
    }

    /* ─────────────────────────────────────────────
     * FIX DISPATCHER
     * ───────────────────────────────────────────── */
    public static function apply_fix($fix_type, $fix_data) {
        switch ($fix_type) {

            case 'quarantine':
            case 'quarantine_rel':
                $file = $fix_data['file'] ?? '';
                if (!$file) return array('success'=>false,'message'=>'No file.');
                $ok = SWPS_File_Integrity::quarantine_file($file);
                return array('success'=>$ok,'message'=>$ok?"Quarantined: $file":"Failed: $file");

            case 'repair_core':
                return SWPS_Core_Repair::repair_file($fix_data['file'] ?? '');

            case 'repair_core_bundle':
                return SWPS_Core_Repair::repair_bundle($fix_data['prefix'] ?? '');

            case 'repair_plugin_file':
                return SWPS_Plugin_Theme_Repair::repair_plugin_file($fix_data['file'] ?? '');

            case 'repair_theme_file':
                return SWPS_Plugin_Theme_Repair::repair_theme_file($fix_data['file'] ?? '');

            case 'update_plugin':
                $slug = $fix_data['slug'] ?? '';
                if (!$slug) return array('success'=>false,'message'=>'No slug.');
                if (!function_exists('wp_update_plugins')) {
                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                    require_once ABSPATH . 'wp-admin/includes/update.php';
                    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
                }
                $plugin_file = '';
                foreach (get_plugins() as $f => $p) {
                    if (strpos($f, $slug.'/') === 0) { $plugin_file = $f; break; }
                }
                if (!$plugin_file) return array('success'=>false,'message'=>"Plugin not found: $slug");
                $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
                $r = $upgrader->upgrade($plugin_file);
                return array('success'=>$r!==false,'message'=>$r!==false?"Updated $slug.":"Update failed.");

            case 'delete_user':
                $uid   = intval($fix_data['user_id'] ?? 0);
                $login = $fix_data['login'] ?? '';
                if (!$uid || $uid === get_current_user_id()) return array('success'=>false,'message'=>'Cannot delete self.');
                require_once ABSPATH . 'wp-admin/includes/user.php';
                $ok = wp_delete_user($uid);
                SWPS_Audit_Trail::log('user_deleted', 'user', $uid, $login, 'Deleted by Full Scan');
                return array('success'=>$ok,'message'=>$ok?"Deleted: $login":"Failed.");

            case 'fix_permissions':
                $path = $fix_data['path'] ?? '';
                $mode = octdec($fix_data['mode'] ?? '0644');
                if (!$path || !file_exists($path)) return array('success'=>false,'message'=>'File not found.');
                $ok = chmod($path, $mode);
                return array('success'=>$ok,'message'=>$ok?"Fixed: ".basename($path):"chmod failed.");

            case 'enable_headers':
                $s = get_option('swps_settings',array());
                $s['security_headers_enabled'] = 1;
                update_option('swps_settings',$s);
                return array('success'=>true,'message'=>'Headers enabled.');

            default:
                return array('success'=>false,'message'=>'Manual action required.');
        }
    }

    /* ─────────────────────────────────────────────
     * HISTORY MANAGEMENT
     * ───────────────────────────────────────────── */
    public static function save_to_history($results, $score) {
        $history = get_option(self::HISTORY_OPT, array());

        $summary = array(
            'scan_id'   => uniqid('scan_'),
            'date'      => time(),
            'score'     => $score['score'],
            'grade'     => $score['grade'],
            'critical'  => 0,
            'warnings'  => 0,
            'total'     => 0,
            'steps_run' => count($results),
        );

        foreach ($results as $step => $data) {
            foreach ($data['issues'] ?? array() as $issue) {
                $summary['total']++;
                if ($issue['severity'] === 'critical') $summary['critical']++;
                else $summary['warnings']++;
            }
        }

        array_unshift($history, $summary);
        if (count($history) > 20) $history = array_slice($history, 0, 20);
        update_option(self::HISTORY_OPT, $history, false);
        return $summary;
    }

    public static function get_history() {
        return get_option(self::HISTORY_OPT, array());
    }

    /* ─────────────────────────────────────────────
     * SCHEDULED SCAN
     * ───────────────────────────────────────────── */
    public static function add_cron_schedule($schedules) {
        if (!isset($schedules['swps_weekly'])) {
            $schedules['swps_weekly'] = array('interval'=>WEEK_IN_SECONDS,'display'=>'Once Weekly');
        }
        return $schedules;
    }

    public static function run_scheduled_scan() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['full_scan_schedule'])) return;

        // Run all steps
        $results = array();
        foreach (array_keys(self::get_steps()) as $step) {
            $disabled = (array)($settings['full_scan_disabled_steps'] ?? array());
            if (in_array($step, $disabled)) continue;
            $issues = self::run_step($step);
            self::store_step_result($step, $issues);
            $results[$step] = array('issues' => $issues);
        }

        $score = self::calculate_score($results);
        self::save_to_history($results, $score);

        // Auto-fix critical if enabled
        if (!empty($settings['full_scan_auto_fix'])) {
            foreach ($results as $step => $data) {
                foreach ($data['issues'] as $issue) {
                    if ($issue['severity'] === 'critical' && $issue['fix'] !== 'none') {
                        self::apply_fix($issue['fix'], $issue['fix_data']);
                    }
                }
            }
        }

        // Send email report
        if (!empty($settings['full_scan_email_report'])) {
            self::send_email_report($results, $score);
        }

        SWPS_Audit_Trail::log('scheduled_scan_complete', 'full_scan', '', '', "Score: {$score['score']}/100 | Grade: {$score['grade']}");
    }

    public static function maybe_reschedule($old, $new) {
        wp_clear_scheduled_hook('swps_scheduled_full_scan');
        $schedule = $new['full_scan_schedule'] ?? '';
        if (!$schedule) return;
        $interval = $schedule === 'daily' ? 'daily' : 'swps_weekly';
        wp_schedule_event(time(), $interval, 'swps_scheduled_full_scan');
    }

    /* ─────────────────────────────────────────────
     * HTML REPORT GENERATOR
     * ───────────────────────────────────────────── */
    public static function generate_html_report($results = null, $score_data = null) {
        if (!$results)    $results    = get_option(self::RESULT_OPT, array());
        if (!$score_data) $score_data = self::calculate_score($results);

        $skipped   = get_option(self::SKIPPED_OPT, array());
        $whitelist = get_option(self::WHITELIST_OPT, array());
        $steps     = self::get_steps();
        $site_name = get_bloginfo('name');
        $site_url  = get_site_url();
        $date      = date('F j, Y H:i');
        $score     = $score_data['score'];
        $grade     = $score_data['grade'];
        $color     = $score_data['color'];

        $critical_count = 0; $warning_count = 0;
        foreach ($results as $data) {
            foreach ($data['issues'] ?? array() as $i) {
                if (in_array($i['id'], $skipped) || in_array($i['id'], $whitelist)) continue;
                if ($i['severity']==='critical') $critical_count++;
                else $warning_count++;
            }
        }

        ob_start(); ?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Security Report — <?php echo esc_html($site_name); ?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1a1a2e;background:#f8f9fa}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:40px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:26px;font-weight:700}
.header .meta{font-size:12px;opacity:.7;margin-top:4px}
.score-circle{width:100px;height:100px;border-radius:50%;background:<?php echo $color; ?>;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;flex-shrink:0}
.score-num{font-size:32px;font-weight:800;line-height:1}
.score-label{font-size:11px;opacity:.8}
.grade{font-size:16px;font-weight:700;margin-top:2px}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px;background:#fff;border-bottom:1px solid #e2e8f0}
.stat{text-align:center;padding:16px}
.stat-num{font-size:32px;font-weight:800}
.stat-label{font-size:12px;color:#64748b;margin-top:4px}
.red{color:#e74c3c}.orange{color:#f39c12}.green{color:#2ecc71}
.section{padding:24px}
.section-title{font-size:16px;font-weight:700;margin-bottom:12px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}
.issue{display:flex;gap:12px;padding:12px;border-radius:6px;margin-bottom:8px;border:1px solid transparent}
.issue-critical{background:#fef2f2;border-color:#fca5a5}
.issue-warning{background:#fffbeb;border-color:#fde68a}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}
.badge-critical{background:#e74c3c}
.badge-warning{background:#f39c12}
.badge-ok{background:#2ecc71}
.issue-title{font-weight:600;font-size:13px}
.issue-detail{font-size:11px;color:#64748b;margin-top:2px}
.step-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f1f5f9}
.footer{padding:24px;text-align:center;font-size:12px;color:#64748b;background:#fff;border-top:1px solid #e2e8f0}
@media print{body{background:#fff}.header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<div class="header">
    <div>
        <h1>🛡️ Security Report</h1>
        <div class="meta"><?php echo esc_html($site_name); ?> — <?php echo esc_html($site_url); ?></div>
        <div class="meta">Generated: <?php echo $date; ?> | By: SecureWP Shield v<?php echo SWPS_VERSION; ?> | Author: <?php echo SWPS_AUTHOR; ?></div>
    </div>
    <div class="score-circle">
        <div class="score-num"><?php echo $score; ?></div>
        <div class="score-label">Security Score</div>
        <div class="grade">Grade <?php echo $grade; ?></div>
    </div>
</div>

<div class="summary">
    <div class="stat"><div class="stat-num red"><?php echo $critical_count; ?></div><div class="stat-label">Critical Issues</div></div>
    <div class="stat"><div class="stat-num orange"><?php echo $warning_count; ?></div><div class="stat-label">Warnings</div></div>
    <div class="stat"><div class="stat-num" style="color:<?php echo $color; ?>"><?php echo $score; ?>/100</div><div class="stat-label">Security Score</div></div>
    <div class="stat"><div class="stat-num"><?php echo count($results); ?></div><div class="stat-label">Checks Run</div></div>
</div>

<?php if ($critical_count > 0): ?>
<div class="section">
    <div class="section-title red">🚨 Critical Issues (<?php echo $critical_count; ?>)</div>
    <?php foreach ($results as $step => $data):
        foreach ($data['issues'] ?? array() as $issue):
            if ($issue['severity'] !== 'critical') continue;
            if (in_array($issue['id'], $skipped) || in_array($issue['id'], $whitelist)) continue;
    ?>
    <div class="issue issue-critical">
        <span class="badge badge-critical">CRITICAL</span>
        <div>
            <div class="issue-title"><?php echo esc_html($issue['title']); ?></div>
            <div class="issue-detail"><?php echo esc_html($issue['detail']); ?></div>
        </div>
    </div>
    <?php endforeach; endforeach; ?>
</div>
<?php endif; ?>

<?php if ($warning_count > 0): ?>
<div class="section">
    <div class="section-title orange">⚠️ Warnings (<?php echo $warning_count; ?>)</div>
    <?php foreach ($results as $step => $data):
        foreach ($data['issues'] ?? array() as $issue):
            if ($issue['severity'] !== 'warning') continue;
            if (in_array($issue['id'], $skipped) || in_array($issue['id'], $whitelist)) continue;
    ?>
    <div class="issue issue-warning">
        <span class="badge badge-warning">WARNING</span>
        <div>
            <div class="issue-title"><?php echo esc_html($issue['title']); ?></div>
            <div class="issue-detail"><?php echo esc_html($issue['detail']); ?></div>
        </div>
    </div>
    <?php endforeach; endforeach; ?>
</div>
<?php endif; ?>

<div class="section">
    <div class="section-title">📊 Scan Summary by Check</div>
    <?php foreach ($steps as $key => $step):
        $data  = $results[$key] ?? null;
        $count = $data ? count($data['issues']??array()) : null;
    ?>
    <div class="step-row">
        <span><?php echo $step['icon']; ?> <?php echo esc_html($step['label']); ?></span>
        <?php if ($data===null): ?>
        <span class="badge" style="background:#64748b">Not Scanned</span>
        <?php elseif ($count===0): ?>
        <span class="badge badge-ok">✓ Clean</span>
        <?php else: ?>
        <span class="badge badge-critical"><?php echo $count; ?> issue(s)</span>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
</div>

<div class="footer">
    Report generated by <strong>SecureWP Shield v<?php echo SWPS_VERSION; ?></strong> — Developed by <strong><?php echo SWPS_AUTHOR; ?></strong><br>
    <?php echo esc_html($site_url); ?> — <?php echo $date; ?>
</div>
</body>
</html>
        <?php
        return ob_get_clean();
    }

    /* ─────────────────────────────────────────────
     * EMAIL REPORT
     * ───────────────────────────────────────────── */
    public static function send_email_report($results = null, $score_data = null) {
        if (!$results)    $results    = get_option(self::RESULT_OPT, array());
        if (!$score_data) $score_data = self::calculate_score($results);

        $settings  = get_option('swps_settings', array());
        $to        = $settings['alert_email'] ?? get_option('admin_email');
        $site_name = get_bloginfo('name');
        $subject   = "[{$site_name}] Security Scan Report — Score: {$score_data['score']}/100 (Grade {$score_data['grade']})";
        $body      = self::generate_html_report($results, $score_data);

        $headers = array('Content-Type: text/html; charset=UTF-8', 'From: SecureWP Shield <' . $to . '>');
        $sent    = wp_mail($to, $subject, $body, $headers);

        SWPS_Audit_Trail::log('scan_report_emailed', 'full_scan', '', $to, "Score: {$score_data['score']} Grade: {$score_data['grade']}");
        return $sent;
    }

    /* ─────────────────────────────────────────────
     * HELPERS
     * ───────────────────────────────────────────── */
    public static function store_step_result($step, $issues) {
        $results = get_option(self::RESULT_OPT, array());
        $results[$step] = array('issues' => $issues, 'scanned_at' => time(), 'count' => count($issues));
        update_option(self::RESULT_OPT, $results, false);
    }

    public static function get_all_issues($results = null) {
        if (!$results) $results = get_option(self::RESULT_OPT, array());
        $all = array();
        foreach ($results as $step => $data) {
            foreach ($data['issues'] ?? array() as $issue) {
                $issue['step'] = $step;
                $all[] = $issue;
            }
        }
        return $all;
    }

    public static function get_summary($results = null) {
        if (!$results) $results = get_option(self::RESULT_OPT, array());
        $skipped   = get_option(self::SKIPPED_OPT, array());
        $whitelist = get_option(self::WHITELIST_OPT, array());
        $critical  = 0; $warnings = 0; $total = 0;

        foreach ($results as $step => $data) {
            foreach ($data['issues'] ?? array() as $issue) {
                if (in_array($issue['id'], $skipped))   continue;
                if (in_array($issue['id'], $whitelist)) continue;
                $total++;
                if ($issue['severity']==='critical') $critical++;
                else $warnings++;
            }
        }

        return array('critical'=>$critical,'warnings'=>$warnings,'total'=>$total,
            'skipped'=>count($skipped),'whitelisted'=>count($whitelist));
    }

    /* ─────────────────────────────────────────────
     * AJAX HANDLERS
     * ───────────────────────────────────────────── */
    public static function ajax_run_step() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $step  = sanitize_key($_POST['step']??'');
        $steps = self::get_steps();
        if (!isset($steps[$step])) wp_send_json_error('Unknown step.');
        $issues = self::run_step($step);
        self::store_step_result($step, $issues);
        // After each step, recalculate score
        $all_results = get_option(self::RESULT_OPT, array());
        $score       = self::calculate_score($all_results);
        wp_send_json_success(array('step'=>$step,'issues'=>$issues,'count'=>count($issues),'score'=>$score));
    }

    public static function ajax_fix() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $fix_type = sanitize_key($_POST['fix_type']??'');
        $fix_data = array();
        foreach ((array)($_POST['fix_data']??array()) as $k=>$v) { $fix_data[sanitize_key($k)]=sanitize_text_field($v); }
        $issue_id = sanitize_text_field($_POST['issue_id']??'');
        $result   = self::apply_fix($fix_type, $fix_data);
        if ($result['success']) {
            // Remove from stored results
            $results = get_option(self::RESULT_OPT, array());
            foreach ($results as $step => &$data) {
                $data['issues'] = array_values(array_filter($data['issues']??array(), function($i) use($issue_id){ return $i['id']!==$issue_id; }));
            }
            update_option(self::RESULT_OPT, $results, false);
            SWPS_Audit_Trail::log('scan_fix_applied','full_scan',$issue_id,$fix_type,$result['message']);
        }
        $score = self::calculate_score(get_option(self::RESULT_OPT,array()));
        wp_send_json_success(array('message'=>$result['message'],'fixed'=>$result['success'],'score'=>$score));
    }

    public static function ajax_fix_all() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $severity = sanitize_text_field($_POST['severity']??'critical');
        $results  = get_option(self::RESULT_OPT, array());
        $skipped  = get_option(self::SKIPPED_OPT, array());
        $fixed    = 0; $failed = 0; $log = array();

        foreach ($results as $step => &$data) {
            foreach ($data['issues']??array() as $idx => $issue) {
                if ($severity !== 'all' && $issue['severity'] !== $severity) continue;
                if (in_array($issue['id'], $skipped)) continue;
                if ($issue['fix'] === 'none' || empty($issue['fix_label'])) continue;
                $r = self::apply_fix($issue['fix'], $issue['fix_data']);
                if ($r['success']) {
                    unset($data['issues'][$idx]);
                    $fixed++;
                    $log[] = '✓ ' . $issue['title'];
                } else {
                    $failed++;
                    $log[] = '✗ ' . $issue['title'] . ': ' . $r['message'];
                }
            }
            $data['issues'] = array_values($data['issues']??array());
        }

        update_option(self::RESULT_OPT, $results, false);
        SWPS_Audit_Trail::log('scan_fix_all','full_scan','','','Fixed: '.$fixed.' Failed: '.$failed);
        $score = self::calculate_score(get_option(self::RESULT_OPT,array()));
        wp_send_json_success(array('fixed'=>$fixed,'failed'=>$failed,'log'=>$log,'score'=>$score));
    }

    public static function ajax_skip() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $id      = sanitize_text_field($_POST['issue_id']??'');
        $skipped = get_option(self::SKIPPED_OPT, array());
        if (!in_array($id, $skipped)) { $skipped[] = $id; update_option(self::SKIPPED_OPT, $skipped); }
        wp_send_json_success('Skipped.');
    }

    public static function ajax_unskip() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $id      = sanitize_text_field($_POST['issue_id']??'');
        $skipped = array_values(array_diff(get_option(self::SKIPPED_OPT,[]),array($id)));
        update_option(self::SKIPPED_OPT, $skipped);
        wp_send_json_success('Unskipped.');
    }

    public static function ajax_whitelist() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $id        = sanitize_text_field($_POST['issue_id']??'');
        $action    = sanitize_key($_POST['wl_action']??'add');
        $whitelist = get_option(self::WHITELIST_OPT, array());
        if ($action === 'remove') {
            $whitelist = array_values(array_diff($whitelist, array($id)));
        } elseif (!in_array($id, $whitelist)) {
            $whitelist[] = $id;
        }
        update_option(self::WHITELIST_OPT, $whitelist);
        wp_send_json_success($action==='remove'?'Removed from whitelist.':'Added to whitelist (will not appear in future scans).');
    }

    public static function ajax_clear() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        delete_option(self::RESULT_OPT);
        delete_option(self::SKIPPED_OPT);
        wp_send_json_success('Cleared.');
    }

    public static function ajax_export_report() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $html     = self::generate_html_report();
        $filename = 'security-report-' . get_bloginfo('name') . '-' . date('Y-m-d') . '.html';
        $filename = sanitize_file_name($filename);
        header('Content-Type: text/html; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo $html;
        exit;
    }

    public static function ajax_email_report() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $sent = self::send_email_report();
        $sent ? wp_send_json_success('Report emailed successfully.') : wp_send_json_error('Email failed. Check WP mail settings.');
    }

    public static function ajax_get_history() {
        check_ajax_referer('swps_nonce','nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        wp_send_json_success(self::get_history());
    }
}
