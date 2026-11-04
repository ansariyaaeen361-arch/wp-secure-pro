<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Uptime_Monitor {

    const OPTION_HISTORY = 'swps_uptime_history';
    const OPTION_STATUS  = 'swps_uptime_status';

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['uptime_enabled'])) return;

        add_action('swps_uptime_check', array(__CLASS__, 'run_check'));
        add_action('wp_ajax_swps_uptime_check_now', array(__CLASS__, 'ajax_check_now'));
        add_action('wp_ajax_swps_uptime_add_url',   array(__CLASS__, 'ajax_add_url'));
        add_action('wp_ajax_swps_uptime_remove_url', array(__CLASS__, 'ajax_remove_url'));

        if (!wp_next_scheduled('swps_uptime_check')) {
            wp_schedule_event(time(), 'swps_5min', 'swps_uptime_check');
        }
    }

    public static function run_check($urls = null) {
        if ($urls === null) {
            $settings = get_option('swps_settings', array());
            $urls = array_filter(array_map('trim', explode("\n", $settings['uptime_urls'] ?? '')));
            if (empty($urls)) {
                $urls = array(get_site_url());
            }
        }

        $history = get_option(self::OPTION_HISTORY, array());
        $status  = get_option(self::OPTION_STATUS,  array());
        $now     = time();

        foreach ($urls as $url) {
            $url    = esc_url_raw(trim($url));
            $result = self::check_url($url);
            $key    = md5($url);

            $was_down = isset($status[$key]) && $status[$key]['status'] === 'down';
            $is_down  = ($result['status'] === 'down');

            $status[$key] = array_merge($result, array(
                'url'      => $url,
                'checked'  => $now,
                'downtime' => $was_down ? ($status[$key]['downtime'] ?? 0) + 5 : 0,
            ));

            // Alert transitions
            $notify = SWPS_Notifications::get_instance();
            if ($is_down && !$was_down) {
                $notify->send(
                    'uptime_down',
                    'Site Down: ' . parse_url($url, PHP_URL_HOST),
                    "**URL:** $url\n**Code:** {$result['code']}\n**Error:** {$result['error']}",
                    'critical'
                );
                SWPS_Audit_Trail::log('site_down', 'uptime', '', $url, "HTTP {$result['code']} — {$result['error']}");
            } elseif (!$is_down && $was_down) {
                $downtime_mins = round(($status[$key]['downtime'] ?? 0));
                $notify->send(
                    'uptime_recovered',
                    'Site Recovered: ' . parse_url($url, PHP_URL_HOST),
                    "**URL:** $url\n**Was down for:** ~{$downtime_mins} minutes",
                    'info'
                );
            }

            // History (keep last 288 checks = 24h at 5-min intervals)
            if (!isset($history[$key])) $history[$key] = array();
            array_push($history[$key], array(
                'time'   => $now,
                'status' => $result['status'],
                'code'   => $result['code'],
                'ms'     => $result['response_ms'],
            ));
            if (count($history[$key]) > 288) {
                $history[$key] = array_slice($history[$key], -288);
            }
        }

        update_option(self::OPTION_STATUS,  $status,  false);
        update_option(self::OPTION_HISTORY, $history, false);

        return $status;
    }

    public static function check_url($url) {
        $start = microtime(true);
        if ( ! self::is_safe_monitor_url( $url ) ) {
            return array( 'status' => 'down', 'code' => 0, 'error' => 'Unsafe monitor URL rejected.', 'response_ms' => 0 );
        }

        $response = wp_safe_remote_get($url, array(
            'timeout'    => 15,
            'user-agent' => 'WP-Secure-Pro/' . SWPS_VERSION . ' Uptime-Monitor',
            'sslverify'  => true,
            'redirection' => 0,
        ));

        $ms = round((microtime(true) - $start) * 1000);

        if (is_wp_error($response)) {
            return array(
                'status'      => 'down',
                'code'        => 0,
                'error'       => $response->get_error_message(),
                'response_ms' => $ms,
            );
        }

        $code = wp_remote_retrieve_response_code($response);
        $ok   = ($code >= 200 && $code < 400);

        return array(
            'status'      => $ok ? 'up' : 'down',
            'code'        => $code,
            'error'       => $ok ? '' : "HTTP $code",
            'response_ms' => $ms,
        );
    }

    private static function is_safe_monitor_url( $url ) {
        $parts = wp_parse_url( $url );
        if ( ! is_array( $parts ) || ( $parts['scheme'] ?? '' ) !== 'https' || empty( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) return false;
        $host = strtolower( rtrim( $parts['host'], '.' ) );
        if ( $host === 'localhost' || substr( $host, -6 ) === '.local' || substr( $host, -9 ) === '.internal' ) return false;
        if ( filter_var( $host, FILTER_VALIDATE_IP ) ) return self::is_public_ip( $host );
        $records = function_exists( 'dns_get_record' ) ? dns_get_record( $host, DNS_A | DNS_AAAA ) : array();
        if ( empty( $records ) ) return false;
        foreach ( $records as $record ) {
            $ip = $record['ip'] ?? ( $record['ipv6'] ?? '' );
            if ( ! self::is_public_ip( $ip ) ) return false;
        }
        return true;
    }

    private static function is_public_ip( $ip ) {
        return (bool) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
    }

    public static function get_stats() {
        $status  = get_option(self::OPTION_STATUS,  array());
        $history = get_option(self::OPTION_HISTORY, array());

        $stats = array();
        foreach ($status as $key => $s) {
            $hist = $history[$key] ?? array();
            $up_count = count(array_filter($hist, fn($h) => $h['status'] === 'up'));
            $uptime_pct = count($hist) > 0 ? round($up_count / count($hist) * 100, 2) : 100;

            $response_times = array_column(array_filter($hist, fn($h) => $h['status'] === 'up'), 'ms');
            $avg_ms = count($response_times) > 0 ? round(array_sum($response_times) / count($response_times)) : 0;

            $stats[$key] = array_merge($s, array(
                'uptime_pct' => $uptime_pct,
                'avg_ms'     => $avg_ms,
                'history'    => array_slice($hist, -48),
            ));
        }

        return $stats;
    }

    public static function ajax_check_now() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $status = self::run_check();
        wp_send_json_success(array('status' => $status, 'message' => 'Check complete.'));
    }

    public static function ajax_add_url() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $url      = esc_url_raw(trim($_POST['url'] ?? ''));
        if (!$url || !filter_var($url, FILTER_VALIDATE_URL) || !self::is_safe_monitor_url($url)) {
            wp_send_json_error('Invalid URL.');
        }
        $settings = get_option('swps_settings', array());
        $urls     = array_filter(array_map('trim', explode("\n", $settings['uptime_urls'] ?? '')));
        if (!in_array($url, $urls)) {
            $urls[] = $url;
            $settings['uptime_urls'] = implode("\n", $urls);
            update_option('swps_settings', $settings);
        }
        wp_send_json_success('URL added.');
    }

    public static function ajax_remove_url() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $url      = esc_url_raw(trim($_POST['url'] ?? ''));
        $settings = get_option('swps_settings', array());
        $urls     = array_filter(array_map('trim', explode("\n", $settings['uptime_urls'] ?? '')));
        $urls     = array_values(array_diff($urls, array($url)));
        $settings['uptime_urls'] = implode("\n", $urls);
        update_option('swps_settings', $settings);

        // Remove stored status/history for this URL
        $key     = md5($url);
        $status  = get_option(self::OPTION_STATUS,  array()); unset($status[$key]);
        $history = get_option(self::OPTION_HISTORY, array()); unset($history[$key]);
        update_option(self::OPTION_STATUS,  $status,  false);
        update_option(self::OPTION_HISTORY, $history, false);

        wp_send_json_success('URL removed.');
    }
}
