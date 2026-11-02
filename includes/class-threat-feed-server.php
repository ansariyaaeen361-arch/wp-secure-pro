<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Threat_Feed_Server {

    const SUBSCRIPTIONS_OPT = 'swps_feed_subscriptions';

    public static function init() {
        // Public feed endpoints (no auth required — read-only)
        add_action('rest_api_init', array(__CLASS__, 'register_endpoints'));

        // Rebuild our own feed, and pull every subscribed feed, on cron —
        // hourly so a newly-blocked IP on one site reaches the others
        // within the hour instead of needing a manual "Import Feed" click.
        add_action('swps_daily_cron',   array(__CLASS__, 'rebuild_feed'));
        add_action('swps_hourly_check', array(__CLASS__, 'sync_subscriptions'));

        // Auto-generate a feed token the moment the server is turned on, so
        // "Enable Threat Feed" never accidentally means "publish our
        // blocklist to the whole internet with no auth" by default.
        add_action('update_option_swps_settings', array(__CLASS__, 'maybe_generate_token'), 10, 2);

        // Fix: WP_REST_Response always gets JSON-encoded by the REST server
        // regardless of a manually set Content-Type header, so the
        // "plain-text, one IP per line" feed was actually being delivered as
        // a single JSON-quoted string — unusable by fail2ban-style
        // consumers (and by our own subscription sync, which parses by
        // real newlines). Intercept just this one route and emit raw text.
        add_filter('rest_pre_serve_request', array(__CLASS__, 'serve_raw_feed'), 10, 4);

        add_action('wp_ajax_swps_feed_rebuild',       array(__CLASS__, 'ajax_rebuild'));
        add_action('wp_ajax_swps_feed_subscribe',     array(__CLASS__, 'ajax_subscribe'));
        add_action('wp_ajax_swps_feed_add_sub',       array(__CLASS__, 'ajax_add_subscription'));
        add_action('wp_ajax_swps_feed_remove_sub',    array(__CLASS__, 'ajax_remove_subscription'));
        add_action('wp_ajax_swps_feed_sync_sub_now',  array(__CLASS__, 'ajax_sync_now'));
    }

    public static function maybe_generate_token($old, $new) {
        if (empty($new['threat_feed_server_enabled']) || !empty($new['threat_feed_token'])) return;
        $new['threat_feed_token'] = wp_generate_password(32, false);
        update_option('swps_settings', $new);
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

    /**
     * Prevents page-cache plugins (LiteSpeed Cache, etc.) from caching a
     * live threat feed — confirmed on a real site that LiteSpeed Cache was
     * serving this endpoint from a 7-day-old cached copy, so subscribers
     * synced a stale blocklist and new IPs never propagated.
     */
    private static function no_cache_headers() {
        if ( ! headers_sent() ) {
            header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
            header( 'X-LiteSpeed-Cache-Control: no-cache' );
        }
        // Response headers alone weren't enough — LiteSpeed Cache's plugin
        // decides REST-route cacheability at its own layer and still cached
        // this endpoint despite the headers above. Its documented API for
        // "don't cache this response" is this action, not a header.
        if ( has_action( 'litespeed_control_set_nocache' ) ) {
            do_action( 'litespeed_control_set_nocache', 'WP Secure Pro: dynamic threat/hub data' );
        }
    }

    /* ── Serve plain-text feed (one IP per line) ── */
    public static function serve_feed($request) {
        self::no_cache_headers();
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
            '# WP Secure Pro Threat Feed',
            '# Site: ' . get_site_url(),
            '# Generated: ' . date('Y-m-d H:i:s', $feed['generated']),
            '# Entries: ' . $feed['count'],
            '#',
        );
        foreach ($feed['entries'] as $entry) {
            $lines[] = $entry['ip'];
        }

        $response = new WP_REST_Response(implode("\n", $lines), 200);
        $response->header('Content-Type', 'text/plain; charset=utf-8');
        return $response;
    }

    /** Emits the plain-text feed route's body raw instead of JSON-encoded. */
    public static function serve_raw_feed($served, $result, $request, $server) {
        if ($request->get_route() !== '/swps/v1/threat-feed') return $served;
        if (!($result instanceof WP_REST_Response) || $result->get_status() !== 200) return $served;
        header('Content-Type: text/plain; charset=utf-8');
        self::no_cache_headers();
        echo $result->get_data();
        return true;
    }

    /* ── Serve JSON feed ── */
    public static function serve_feed_json($request) {
        self::no_cache_headers();
        $settings = get_option('swps_settings', array());
        if (empty($settings['threat_feed_server_enabled'])) {
            return new WP_Error('disabled', 'Threat feed is disabled.', array('status' => 403));
        }

        // Fix: this endpoint skipped the token check that serve_feed() (the
        // plain-text variant) already enforces — an owner who set a token
        // believing it protected "the threat feed" had the JSON copy of the
        // same data left wide open.
        $feed_token = $settings['threat_feed_token'] ?? '';
        if ($feed_token) {
            $req_token = $request->get_header('X-Feed-Token') ?: ($request->get_param('token') ?: '');
            if (!hash_equals($feed_token, (string)$req_token)) {
                return new WP_Error('auth', 'Invalid token.', array('status' => 401));
            }
        }

        $feed = get_option('swps_threat_feed_cache', null);
        if (!$feed) $feed = self::build_feed();

        return rest_ensure_response($feed);
    }

    public static function serve_feed_info() {
        self::no_cache_headers();
        $settings = get_option('swps_settings', array());
        if (empty($settings['threat_feed_server_enabled'])) {
            return new WP_Error('disabled', 'Threat feed is disabled.', array('status' => 403));
        }
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

    /** One-shot import — kept for backward compatibility with the old UI. */
    public static function ajax_subscribe() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $feed_url = esc_url_raw(trim($_POST['feed_url'] ?? ''));
        $token    = sanitize_text_field($_POST['feed_token'] ?? '');
        if (!$feed_url) wp_send_json_error('Invalid feed URL.');

        $result = self::fetch_and_import($feed_url, $token);
        if (is_wp_error($result)) wp_send_json_error($result->get_error_message());
        wp_send_json_success("Imported {$result} IPs from external feed.");
    }

    /* ── Persistent subscriptions — synced automatically every hour ── */

    public static function get_subscriptions() {
        return get_option(self::SUBSCRIPTIONS_OPT, array());
    }

    public static function ajax_add_subscription() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

        $url   = esc_url_raw(trim($_POST['feed_url'] ?? ''));
        $token = sanitize_text_field($_POST['feed_token'] ?? '');
        $name  = sanitize_text_field($_POST['name'] ?? '') ?: parse_url($url, PHP_URL_HOST);
        if (!$url) wp_send_json_error('Invalid feed URL.');

        $subs = self::get_subscriptions();
        $id   = md5($url);
        $subs[$id] = array(
            'id' => $id, 'url' => $url, 'token' => $token, 'name' => $name,
            'added' => time(), 'last_sync' => null, 'last_count' => 0, 'last_error' => '',
        );
        update_option(self::SUBSCRIPTIONS_OPT, $subs);

        // Sync immediately so the owner sees a result without waiting an hour.
        self::sync_one($subs[$id]);

        wp_send_json_success(array('subscriptions' => self::get_subscriptions()));
    }

    public static function ajax_remove_subscription() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $id   = sanitize_text_field($_POST['id'] ?? '');
        $subs = self::get_subscriptions();
        unset($subs[$id]);
        update_option(self::SUBSCRIPTIONS_OPT, $subs);
        wp_send_json_success('Removed.');
    }

    public static function ajax_sync_now() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        self::sync_subscriptions();
        wp_send_json_success(array('subscriptions' => self::get_subscriptions()));
    }

    /** Hourly cron: pull every saved subscription and import new IPs. */
    public static function sync_subscriptions() {
        foreach (self::get_subscriptions() as $sub) {
            self::sync_one($sub);
        }
    }

    private static function sync_one($sub) {
        $subs = self::get_subscriptions();
        $id   = $sub['id'];
        if (!isset($subs[$id])) return;

        $result = self::fetch_and_import($sub['url'], $sub['token'] ?? '');
        if (is_wp_error($result)) {
            $subs[$id]['last_error'] = $result->get_error_message();
        } else {
            $subs[$id]['last_error']  = '';
            $subs[$id]['last_count']  = $result;
            $subs[$id]['last_sync']   = time();
        }
        update_option(self::SUBSCRIPTIONS_OPT, $subs);
    }

    /** Shared fetch+parse+block logic for both one-shot and scheduled imports. */
    private static function fetch_and_import($feed_url, $token = '') {
        $args = array('timeout' => 15);
        if ($token) $args['headers'] = array('X-Feed-Token' => $token);

        $resp = wp_remote_get($feed_url, $args);
        if (is_wp_error($resp)) return $resp;

        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return new WP_Error('feed_http_' . $code, "Feed returned HTTP $code" . ($code === 401 ? ' — check the feed token.' : '.'));
        }

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

        return $count;
    }
}
