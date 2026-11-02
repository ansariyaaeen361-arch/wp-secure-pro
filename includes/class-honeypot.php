<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Honeypot {

    const TRAPS_OPT = 'swps_honeypot_traps';
    const LOG_OPT   = 'swps_honeypot_log';

    /* Default trap slugs — look like juicy targets */
    const DEFAULT_TRAPS = array(
        'wp-admin/setup-config.php',
        'wp-admin/install.php',
        'backup.zip',
        'backup.sql',
        'db-backup.sql',
        '.env',
        'config.php',
        'wp-config-backup.php',
        'xmlrpc.php',
        'wp-content/uploads/shell.php',
        'admin/config.php',
        'phpmyadmin',
        'adminer.php',
        'setup.php',
    );

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['honeypot_enabled'])) return;

        add_action('init',                          array(__CLASS__, 'intercept_traps'), 2);
        add_action('wp_ajax_swps_honeypot_add',     array(__CLASS__, 'ajax_add_trap'));
        add_action('wp_ajax_swps_honeypot_remove',  array(__CLASS__, 'ajax_remove_trap'));
        add_action('wp_ajax_swps_honeypot_clear',   array(__CLASS__, 'ajax_clear_log'));
    }

    /* ── Main interceptor — runs on every request ── */
    public static function intercept_traps() {
        $traps    = self::get_traps();
        $uri      = ltrim(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '', '/');
        $ip       = SWPS_IP_Blocker::get_ip();
        $settings = get_option('swps_settings', array());

        foreach ($traps as $trap) {
            $trap_clean = ltrim($trap, '/');

            // Exact match or starts-with match
            if ($uri === $trap_clean || strpos($uri, $trap_clean) === 0) {
                self::trigger($ip, $uri, $trap_clean);

                // Auto-block the attacker
                if (!empty($settings['honeypot_auto_block'])) {
                    SWPS_IP_Blocker::block_ip($ip, "Honeypot triggered: /$trap_clean", intval($settings['honeypot_block_duration'] ?? 1440));
                }

                // Fake response — don't reveal it's a trap
                $fake_mode = $settings['honeypot_response'] ?? 'fake_404';
                if ($fake_mode === 'fake_200') {
                    status_header(200);
                    echo '<!DOCTYPE html><html><head><title>Index</title></head><body></body></html>';
                } elseif ($fake_mode === 'redirect_home') {
                    wp_safe_redirect(home_url());
                } else {
                    status_header(404);
                    echo '<!DOCTYPE html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>';
                }
                exit;
            }
        }
    }

    /* ── Log and alert the hit ── */
    public static function trigger($ip, $uri, $trap) {
        $log = get_option(self::LOG_OPT, array());

        $entry = array(
            'time'    => time(),
            'ip'      => $ip,
            'uri'     => $uri,
            'trap'    => $trap,
            'ua'      => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
            'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'country' => class_exists('SWPS_GeoIP') ? SWPS_GeoIP::get_country($ip) : '',
        );

        array_push($log, $entry);
        if (count($log) > 500) $log = array_slice($log, -500);
        update_option(self::LOG_OPT, $log, false);

        // Fix (explicit, repeated user complaint — real inbox evidence: 50+
        // emails in under 24h, almost all for /xmlrpc.php and /.env* probes,
        // which every automated internet-wide bot scanner hits on literally
        // every WordPress site constantly, attacker or not): this used to
        // email on EVERY single trap hit, with no throttle at all. Blocking
        // and logging the hit stays fully real-time (unchanged above/below)
        // — only the EMAIL is now throttled, to at most one every 30
        // minutes, and that one email summarizes every hit (count + distinct
        // IPs) since the last email instead of losing the rest silently.
        if (class_exists('SWPS_Notifications')) {
            $cooldown_key = 'swps_honeypot_email_cooldown';
            if (! get_transient($cooldown_key)) {
                set_transient($cooldown_key, time(), 30 * MINUTE_IN_SECONDS);
                $last_sent = get_option('swps_honeypot_last_email_at', 0);
                $since = array_filter($log, fn($e) => $e['time'] > $last_sent);
                $count = count($since);
                $ips   = array_unique(array_column($since, 'ip'));
                $body  = $count > 1
                    ? "**$count honeypot hit(s)** from " . count($ips) . " IP(s) since the last alert — most recent:\n\n"
                        . "**IP:** $ip\n**URL:** /{$uri}\n**Trap:** /{$trap}\n\n"
                        . "(Further hits in the next 30 minutes are logged and auto-blocked as usual, but won't each trigger a separate email — check Monitoring & Logs for the full list.)"
                    : "**IP:** $ip\n**URL:** /{$uri}\n**Trap:** /{$trap}";

                $notify = SWPS_Notifications::get_instance();
                $notify->send( 'honeypot_triggered', 'Honeypot Triggered', $body, 'critical' );
                update_option('swps_honeypot_last_email_at', time(), false);
            }
        }

        SWPS_Audit_Trail::log('honeypot_triggered', 'honeypot', '', "/$trap", "IP: $ip — URI: /$uri");

        // AbuseIPDB report
        if (class_exists('SWPS_Threat_Feed')) {
            SWPS_Threat_Feed::report_ip($ip, array(21), "Honeypot triggered at /$trap");
        }

        // Reputation score boost
        if (class_exists('SWPS_IP_Reputation')) {
            SWPS_IP_Reputation::record_event($ip, 'honeypot', 40);
        }
    }

    /* ── Trap list management ── */
    public static function get_traps() {
        $custom = get_option(self::TRAPS_OPT, null);
        if ($custom === null) {
            update_option(self::TRAPS_OPT, self::DEFAULT_TRAPS);
            return self::DEFAULT_TRAPS;
        }
        return (array) $custom;
    }

    public static function ajax_add_trap() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $slug  = ltrim(sanitize_text_field($_POST['slug'] ?? ''), '/');
        if (!$slug) wp_send_json_error('Empty slug.');
        $traps = self::get_traps();
        if (!in_array($slug, $traps)) { $traps[] = $slug; update_option(self::TRAPS_OPT, $traps); }
        wp_send_json_success('Trap added.');
    }

    public static function ajax_remove_trap() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $slug  = ltrim(sanitize_text_field($_POST['slug'] ?? ''), '/');
        $traps = array_values(array_diff(self::get_traps(), array($slug)));
        update_option(self::TRAPS_OPT, $traps);
        wp_send_json_success('Trap removed.');
    }

    public static function ajax_clear_log() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        delete_option(self::LOG_OPT);
        wp_send_json_success('Log cleared.');
    }

    public static function get_log($limit = 100) {
        $log = get_option(self::LOG_OPT, array());
        return array_slice(array_reverse($log), 0, $limit);
    }

    public static function get_stats() {
        $log = get_option(self::LOG_OPT, array());
        $ips = array_count_values(array_column($log, 'ip'));
        arsort($ips);
        return array(
            'total_hits'  => count($log),
            'unique_ips'  => count($ips),
            'top_ips'     => array_slice($ips, 0, 5, true),
            'trap_count'  => count(self::get_traps()),
        );
    }
}
