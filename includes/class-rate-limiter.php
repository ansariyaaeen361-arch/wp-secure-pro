<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Rate_Limiter {

    /* Default rules: endpoint_key => [limit, window_seconds, block_seconds] */
    const DEFAULT_RULES = array(
        'login'       => array('limit' => 10,  'window' => 60,   'block' => 300),
        'register'    => array('limit' => 5,   'window' => 3600, 'block' => 3600),
        'xmlrpc'      => array('limit' => 5,   'window' => 60,   'block' => 1440 * 60),
        'rest_api'    => array('limit' => 100, 'window' => 60,   'block' => 60),
        'comments'    => array('limit' => 10,  'window' => 60,   'block' => 300),
        'search'      => array('limit' => 30,  'window' => 60,   'block' => 120),
        'global'      => array('limit' => 300, 'window' => 60,   'block' => 120),
    );

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['rate_limiter_enabled'])) return;

        add_action('init', array(__CLASS__, 'check_global'), 1);
        add_filter('authenticate', array(__CLASS__, 'check_login'), 1, 3);
        add_action('login_form_register', array(__CLASS__, 'check_register'));
        add_action('xmlrpc_call',  array(__CLASS__, 'check_xmlrpc'));
        add_action('rest_api_init', array(__CLASS__, 'hook_rest'));
        add_filter('preprocess_comment', array(__CLASS__, 'check_comment'));
        add_action('pre_get_posts', array(__CLASS__, 'check_search'));
        add_action('wp_ajax_swps_rate_limit_clear', array(__CLASS__, 'ajax_clear_log'));
    }

    public static function ajax_clear_log() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        delete_option('swps_rate_limit_log');
        wp_send_json_success('Log cleared.');
    }

    /* ── Core rate-check engine ── */
    public static function check($endpoint, $ip = null) {
        if (!$ip) $ip = SWPS_IP_Blocker::get_ip();

        // Whitelisted?
        if (SWPS_IP_Blocker::is_whitelisted($ip)) return true;

        $rules    = self::get_rules();
        $rule     = $rules[$endpoint] ?? $rules['global'];
        $key      = 'swps_rl_' . $endpoint . '_' . md5($ip);

        // Fix: a rate-limit block used to live only in a transient — a
        // second, invisible blocking mechanism the IP Blocker admin page
        // had no idea existed, so a blocked automation/bot IP showed
        // nowhere in "Currently Blocked IPs" and there was no Unblock
        // button for it (confirmed: the only "fix" was waiting out the
        // transient, or deleting it by hand in the database). Recording the
        // block through SWPS_IP_Blocker::block_ip() instead puts it in the
        // exact same table/list/Unblock flow as every other block, and
        // checking is_blocked() here means clicking that Unblock button
        // actually lifts a rate-limit block immediately — not just hides it.
        if ( SWPS_IP_Blocker::is_blocked( $ip ) ) {
            self::block_response($endpoint, $ip);
        }

        // Increment counter
        $count = (int)(get_transient($key) ?: 0) + 1;
        set_transient($key, $count, $rule['window']);

        if ($count > $rule['limit']) {
            SWPS_IP_Blocker::block_ip( $ip, "Rate limit exceeded: $endpoint ($count requests in {$rule['window']}s)", round($rule['block'] / 60) ?: 1 );
            self::log_rate_limit($ip, $endpoint, $count, $rule);
            self::block_response($endpoint, $ip);
        }

        return true;
    }

    /* ── Block response (terminates request) ── */
    private static function block_response($endpoint, $ip) {
        $rules   = self::get_rules();
        $rule    = $rules[$endpoint] ?? $rules['global'];
        $minutes = round($rule['block'] / 60);

        // Report to reputation engine
        if (class_exists('SWPS_IP_Reputation')) {
            SWPS_IP_Reputation::record_event($ip, 'rate_limit', 10);
        }

        status_header(429);
        header('Retry-After: ' . $rule['block']);
        header('Content-Type: application/json');
        echo json_encode(array(
            'error'   => 'Too Many Requests',
            'message' => "Rate limit exceeded. Try again in $minutes minute(s).",
            'endpoint'=> $endpoint,
        ));
        exit;
    }

    /* ── Log event ── */
    private static function log_rate_limit($ip, $endpoint, $count, $rule) {
        $log = get_option('swps_rate_limit_log', array());
        array_push($log, array(
            'time'     => time(),
            'ip'       => $ip,
            'endpoint' => $endpoint,
            'count'    => $count,
            'limit'    => $rule['limit'],
            'window'   => $rule['window'],
        ));
        if (count($log) > 200) $log = array_slice($log, -200);
        update_option('swps_rate_limit_log', $log, false);

        SWPS_Audit_Trail::log('rate_limit_exceeded', 'rate_limiter', '', $endpoint, "IP: $ip — {$count} req in {$rule['window']}s");
    }

    /* ── Endpoint hooks ── */
    public static function check_global() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) return;
        if (defined('REST_REQUEST') && REST_REQUEST) return;
        self::check('global');
    }

    public static function check_login($user, $username, $password) {
        if (!empty($username)) self::check('login');
        return $user;
    }

    public static function check_register() {
        self::check('register');
    }

    public static function check_xmlrpc($method) {
        self::check('xmlrpc');
    }

    public static function hook_rest() {
        add_action('rest_pre_dispatch', function($result, $server, $request) {
            // Fix: this limit (100 req/min by default) was applied to EVERY
            // REST request, authenticated or not — so a site owner's own
            // automation/bot using an Application Password got rate-limited
            // and effectively blocked just for doing real, legitimate work
            // at any real volume. An authenticated request (valid App
            // Password, cookie+nonce, or any other auth method WordPress
            // accepted before this hook ran) is by definition not an
            // anonymous abuser — only anonymous/unauthenticated REST
            // traffic is rate-limited now.
            if ( ! is_user_logged_in() ) {
                SWPS_Rate_Limiter::check('rest_api');
            }
            return $result;
        }, 10, 3);
    }

    public static function check_comment($commentdata) {
        self::check('comments');
        return $commentdata;
    }

    public static function check_search($query) {
        if ($query->is_main_query() && $query->is_search()) {
            self::check('search');
        }
    }

    /* ── Rules management ── */
    public static function get_rules() {
        $custom = get_option('swps_rate_rules', array());
        return array_merge(self::DEFAULT_RULES, $custom);
    }

    public static function get_stats() {
        $log = get_option('swps_rate_limit_log', array());
        $eps = array_count_values(array_column($log, 'endpoint'));
        $ips = array_count_values(array_column($log, 'ip'));
        arsort($ips);
        return array(
            'total_blocks' => count($log),
            'by_endpoint'  => $eps,
            'top_ips'      => array_slice($ips, 0, 5, true),
            'recent'       => array_slice(array_reverse($log), 0, 20),
        );
    }
}
