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

        $response = wp_remote_get($url, array(
            'timeout'    => 15,
            'user-agent' => 'WP-Secure-Pro/' . SWPS_VERSION . ' Uptime-Monitor',
            'sslverify'  => false,
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
        if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
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
