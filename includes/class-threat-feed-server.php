<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Threat_Feed_Server {

    public static function init() {
        // Public feed endpoints (no auth required — read-only)
        add_action('rest_api_init', array(__CLASS__, 'register_endpoints'));

        // Rebuild feed on daily cron
        add_action('swps_daily_cron', array(__CLASS__, 'rebuild_feed'));

        add_action('wp_ajax_swps_feed_rebuild', array(__CLASS__, 'ajax_rebuild'));
        add_action('wp_ajax_swps_feed_subscribe', array(__CLASS__, 'ajax_subscribe'));
    }

    /* ── REST endpoints ── */
    public static function register_endpoints() {
        // IP blocklist — plain text (one IP per line, like fail2ban)
        register_rest_route('swps/v1', '/threat-feed', array(
            'methods'             => 'GET',
            'callback'            => array(__CLASS__, 'serve_feed'),
            'permission_callback' => '__return_true',
        ));

        // JSON feed with metadata
        register_rest_route('swps/v1', '/threat-feed/json', array(
            'methods'             => 'GET',
            'callback'            => array(__CLASS__, 'serve_feed_json'),
            'permission_callback' => '__return_true',
        ));

        // Feed info/stats
        register_rest_route('swps/v1', '/threat-feed/info', array(
            'methods'             => 'GET',
            'callback'            => array(__CLASS__, 'serve_feed_info'),
            'permission_callback' => '__return_true',
        ));
    }

    /* ── Build the blocklist from all sources ── */
    public static function build_feed() {
        $settings   = get_option('swps_settings', array());
        $min_score  = intval($settings['feed_min_score'] ?? 75);
        $max_entries= intval($settings['feed_max_entries'] ?? 5000);

        $ips = array();

        // 1. Manually blocked IPs
        $blocked = (array)get_option('swps_blocked_ips', array());
        foreach ($blocked as $ip => $data) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[$ip] = array(
                    'ip'       => $ip,
                    'score'    => 100,
                    'reason'   => $data['reason'] ?? 'manual_block',
                    'since'    => $data['time'] ?? time(),
                    'source'   => 'manual',
                );
            }
        }

        // 2. High-reputation-score IPs
        if (class_exists('SWPS_IP_Reputation')) {
            $rep = SWPS_IP_Reputation::get_top_threats(500);
            foreach ($rep as $record) {
                $ip = $record['ip'] ?? '';
                if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
                if ($record['score'] >= $min_score) {
                    $ips[$ip] = array(
                        'ip'     => $ip,
                        'score'  => $record['score'],
                        'reason' => 'reputation_score',
                        'since'  => $record['last_event'] ?? time(),
                        'source' => 'reputation',
                    );
                }
            }
        }

        // 3. Honeypot IPs
        if (class_exists('SWPS_Honeypot')) {
            $hp_log = get_option(SWPS_Honeypot::LOG_OPT, array());
            $hp_ips = array_unique(array_column($hp_log, 'ip'));
            foreach ($hp_ips as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) && !isset($ips[$ip])) {
                    $ips[$ip] = array('ip'=>$ip,'score'=>80,'reason'=>'honeypot','since'=>time(),'source'=>'honeypot');
                }
            }
        }

        // 4. Fake login IPs
        if (class_exists('SWPS_Fake_Login')) {
            $fl_log = get_option(SWPS_Fake_Login::LOG_OPT, array());
            foreach (array_filter($fl_log, fn($e) => $e['type'] === 'credentials') as $e) {
                $ip = $e['ip'] ?? '';
                if (filter_var($ip, FILTER_VALIDATE_IP) && !isset($ips[$ip])) {
                    $ips[$ip] = array('ip'=>$ip,'score'=>90,'reason'=>'fake_login','since'=>$e['time']??time(),'source'=>'fake_login');
                }
            }
        }

        // Remove private/reserved IPs
        $ips = array_filter($ips, function($entry) {
            $ip = $entry['ip'];
            return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
        });

        // Sort by score desc, limit
        uasort($ips, fn($a, $b) => $b['score'] <=> $a['score']);
        $ips = array_slice($ips, 0, $max_entries, true);

        $feed = array(
            'generated'  => time(),
            'count'      => count($ips),
            'site_url'   => get_site_url(),
            'version'    => '1.0',
            'entries'    => array_values($ips),
        );

        update_option('swps_threat_feed_cache', $feed, false);
        return $feed;
    }

    public static function rebuild_feed() {
        $settings = get_option('swps_settings', array());
        if (!empty($settings['threat_feed_server_enabled'])) {
            self::build_feed();
        }
    }

    /* ── Serve plain-text feed (one IP per line) ── */
    public static function serve_feed($request) {
        $settings = get_option('swps_settings', array());
        if (empty($settings['threat_feed_server_enabled'])) {
            return new WP_Error('disabled', 'Threat feed is disabled.', array('status' => 403));
        }

        // Optional token protection
        $feed_token = $settings['threat_feed_token'] ?? '';
        if ($feed_token) {
            $req_token = $request->get_header('X-Feed-Token') ?: ($request->get_param('token') ?: '');
            if (!hash_equals($feed_token, (string)$req_token)) {
                return new WP_Error('auth', 'Invalid token.', array('status' => 401));
            }
        }

        $feed = get_option('swps_threat_feed_cache', null);
        if (!$feed) $feed = self::build_feed();

        $lines = array(
            '# SecureWP Shield Threat Feed',
            '# Site: ' . get_site_url(),
            '# Generated: ' . date('Y-m-d H:i:s', $feed['generated']),
            '# Entries: ' . $feed['count'],
            '#',
        );
        foreach ($feed['entries'] as $entry) {
            $lines[] = $entry['ip'];
        }

        return new WP_REST_Response(implode("\n", $lines), 200, array('Content-Type' => 'text/plain; charset=utf-8'));
    }

    /* ── Serve JSON feed ── */
    public static function serve_feed_json($request) {
        $settings = get_option('swps_settings', array());
        if (empty($settings['threat_feed_server_enabled'])) {
            return new WP_Error('disabled', 'Threat feed is disabled.', array('status' => 403));
        }

        $feed = get_option('swps_threat_feed_cache', null);
        if (!$feed) $feed = self::build_feed();

        return rest_ensure_response($feed);
    }

    public static function serve_feed_info() {
        $feed = get_option('swps_threat_feed_cache', array());
        return rest_ensure_response(array(
            'site_url'   => get_site_url(),
            'generated'  => $feed['generated'] ?? null,
            'count'      => $feed['count'] ?? 0,
            'feed_url'   => get_rest_url(null, 'swps/v1/threat-feed'),
            'json_url'   => get_rest_url(null, 'swps/v1/threat-feed/json'),
            'version'    => '1.0',
        ));
    }

    public static function ajax_rebuild() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $feed = self::build_feed();
        wp_send_json_success(array('count' => $feed['count'], 'generated' => date('Y-m-d H:i:s', $feed['generated'])));
    }

    public static function ajax_subscribe() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        // Subscribe this site to an external feed
        $feed_url = esc_url_raw(trim($_POST['feed_url'] ?? ''));
        if (!$feed_url) wp_send_json_error('Invalid feed URL.');

        $resp = wp_remote_get($feed_url, array('timeout' => 15));
        if (is_wp_error($resp)) wp_send_json_error($resp->get_error_message());

        $body  = wp_remote_retrieve_body($resp);
        $lines = array_filter(explode("\n", $body), fn($l) => trim($l) && $l[0] !== '#');
        $count = 0;

        foreach ($lines as $line) {
            $ip = trim($line);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                SWPS_IP_Blocker::block_ip($ip, "External threat feed: $feed_url", 10080);
                $count++;
            }
        }

        wp_send_json_success("Imported $count IPs from external feed.");
    }
}
