<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Multisite_Monitor {

    const SITES_OPT  = 'swps_monitored_sites';
    const DATA_OPT   = 'swps_sites_data';

    public static function init() {
        // Register REST endpoint so other sites can push data to this hub
        add_action('rest_api_init', array(__CLASS__, 'register_rest_endpoints'));

        add_action('swps_hourly_check',           array(__CLASS__, 'poll_all_sites'));
        add_action('wp_ajax_swps_ms_add_site',    array(__CLASS__, 'ajax_add_site'));
        add_action('wp_ajax_swps_ms_remove_site', array(__CLASS__, 'ajax_remove_site'));
        add_action('wp_ajax_swps_ms_poll_now',    array(__CLASS__, 'ajax_poll_now'));
    }

    /* ── REST: agent sites push their status here ── */
    public static function register_rest_endpoints() {
        register_rest_route('swps/v1', '/status', array(
            'methods'             => 'POST',
            'callback'            => array(__CLASS__, 'rest_receive_status'),
            'permission_callback' => array(__CLASS__, 'rest_auth'),
        ));

        register_rest_route('swps/v1', '/status', array(
            'methods'             => 'GET',
            'callback'            => array(__CLASS__, 'rest_get_status'),
            'permission_callback' => array(__CLASS__, 'rest_auth'),
        ));
    }

    public static function rest_auth($request) {
        $token    = $request->get_header('X-SWPS-Token');
        $settings = get_option('swps_settings', array());
        $secret   = $settings['ms_hub_secret'] ?? '';
        return !empty($secret) && hash_equals($secret, (string)$token);
    }

    /** See SWPS_Threat_Feed_Server::no_cache_headers() — same page-cache
     *  issue (confirmed with LiteSpeed Cache) applies to this hub data. */
    private static function no_cache_headers() {
        if ( ! headers_sent() ) {
            header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
            header( 'X-LiteSpeed-Cache-Control: no-cache' );
        }
        if ( has_action( 'litespeed_control_set_nocache' ) ) {
            do_action( 'litespeed_control_set_nocache', 'SecureWP Shield: dynamic threat/hub data' );
        }
    }

    /* ── Receive status push from an agent site ── */
    public static function rest_receive_status($request) {
        self::no_cache_headers();
        $data     = $request->get_json_params();
        $site_url = sanitize_url($data['site_url'] ?? '');
        if (!$site_url) return new WP_Error('invalid', 'Missing site_url', array('status' => 400));

        $all  = get_option(self::DATA_OPT, array());
        $key  = md5($site_url);

        $all[$key] = array_merge($all[$key] ?? array(), array(
            'site_url'    => $site_url,
            'site_name'   => sanitize_text_field($data['site_name'] ?? ''),
            'last_push'   => time(),
            'wp_version'  => sanitize_text_field($data['wp_version'] ?? ''),
            'blocked_ips' => intval($data['blocked_ips'] ?? 0),
            'threats_24h' => intval($data['threats_24h'] ?? 0),
            'critical_events' => intval($data['critical_events'] ?? 0),
            'ssl_days'    => intval($data['ssl_days'] ?? 0),
            'fim_changes' => intval($data['fim_changes'] ?? 0),
            'score'       => intval($data['score'] ?? 100),
            'alerts'      => (array)($data['alerts'] ?? array()),
            'status'      => 'online',
        ));

        update_option(self::DATA_OPT, $all, false);
        return rest_ensure_response(array('success' => true, 'received_at' => date('c')));
    }

    /* ── GET: return hub summary for dashboards ── */
    public static function rest_get_status($request) {
        self::no_cache_headers();
        $data = get_option(self::DATA_OPT, array());
        return rest_ensure_response(array('sites' => array_values($data), 'count' => count($data)));
    }

    /* ── Poll agent sites via their SWPS REST API ── */
    public static function poll_all_sites() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['ms_hub_enabled'])) return;

        $sites = get_option(self::SITES_OPT, array());
        $all   = get_option(self::DATA_OPT, array());

        foreach ($sites as $site) {
            $url    = rtrim($site['url'], '/') . '/wp-json/swps/v1/status';
            $result = wp_remote_get($url, array(
                'headers' => array('X-SWPS-Token' => $site['token']),
                'timeout' => 10,
            ));

            $key = md5($site['url']);

            if (is_wp_error($result)) {
                $all[$key] = array_merge($all[$key] ?? array(), array(
                    'site_url'  => $site['url'],
                    'status'    => 'offline',
                    'last_poll' => time(),
                    'error'     => $result->get_error_message(),
                ));
            } else {
                $body = json_decode(wp_remote_retrieve_body($result), true);
                $all[$key] = array_merge($all[$key] ?? array(), $body ?? array(), array(
                    'last_poll' => time(),
                    'status'    => 'online',
                    'site_url'  => $site['url'],
                ));
            }
        }

        update_option(self::DATA_OPT, $all, false);
    }

    /* ── Push this site's own status to a hub ── */
    public static function push_to_hub() {
        $settings = get_option('swps_settings', array());
        $hub_url  = $settings['ms_hub_url'] ?? '';
        $token    = $settings['ms_agent_token'] ?? '';
        if (!$hub_url || !$token) return false;

        $payload = array(
            'site_url'       => get_site_url(),
            'site_name'      => get_bloginfo('name'),
            'wp_version'     => get_bloginfo('version'),
            'blocked_ips'    => count((array)get_option('swps_blocked_ips', array())),
            'threats_24h'    => self::count_recent_threats(),
            'score'          => SWPS_Full_Scan::calculate_score()['score'] ?? 100,
            'ssl_days'       => SWPS_SSL_Monitor::get_last_check()['days_remaining'] ?? 0,
            'fim_changes'    => count(get_option('swps_fim_changes', array())),
            'critical_events'=> self::count_critical_events(),
        );

        $resp = wp_remote_post(rtrim($hub_url, '/') . '/wp-json/swps/v1/status', array(
            'headers' => array('Content-Type' => 'application/json', 'X-SWPS-Token' => $token),
            'body'    => json_encode($payload),
            'timeout' => 10,
        ));

        return !is_wp_error($resp);
    }

    private static function count_recent_threats() {
        $log = get_option('swps_live_traffic_log', array());
        $cutoff = time() - DAY_IN_SECONDS;
        return count(array_filter($log, fn($e) => ($e['time'] ?? 0) >= $cutoff && !empty($e['blocked'])));
    }

    private static function count_critical_events() {
        global $wpdb;
        $table = $wpdb->prefix . 'swps_audit_trail';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table'") !== $table) return 0; // phpcs:ignore
        return (int)$wpdb->get_var($wpdb->prepare( // phpcs:ignore
            "SELECT COUNT(*) FROM $table WHERE created_at >= %s", // phpcs:ignore
            date('Y-m-d H:i:s', time() - DAY_IN_SECONDS)
        ));
    }

    public static function get_sites_data() {
        return get_option(self::DATA_OPT, array());
    }

    public static function ajax_add_site() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $url   = esc_url_raw(trim($_POST['url'] ?? ''));
        $token = sanitize_text_field($_POST['token'] ?? '');
        $name  = sanitize_text_field($_POST['name'] ?? '');
        if (!$url) wp_send_json_error('Invalid URL.');
        $sites = get_option(self::SITES_OPT, array());
        $sites[md5($url)] = array('url' => $url, 'token' => $token, 'name' => $name, 'added' => time());
        update_option(self::SITES_OPT, $sites);
        wp_send_json_success('Site added.');
    }

    public static function ajax_remove_site() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $url   = esc_url_raw(trim($_POST['url'] ?? ''));
        $sites = get_option(self::SITES_OPT, array()); unset($sites[md5($url)]);
        $all   = get_option(self::DATA_OPT,  array()); unset($all[md5($url)]);
        update_option(self::SITES_OPT, $sites);
        update_option(self::DATA_OPT,  $all, false);
        wp_send_json_success('Site removed.');
    }

    public static function ajax_poll_now() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        self::poll_all_sites();
        wp_send_json_success(array('data' => self::get_sites_data(), 'message' => 'Poll complete.'));
    }
}
