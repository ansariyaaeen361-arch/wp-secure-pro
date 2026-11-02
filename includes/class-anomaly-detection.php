<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Anomaly_Detection {

    public static function init() {
        // Triggered from session manager and login protection
    }

    /**
     * Check for anomalies after a successful login.
     */
    public static function check_login( $user, $ip ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['anomaly_detection_enabled']) ) return;

        $anomalies = array();

        // 1. New country
        $country    = self::get_country($ip);
        $known_countries = get_user_meta($user->ID, '_swps_known_countries', true) ?: array();
        if ( $country && ! empty($known_countries) && ! in_array($country, $known_countries) ) {
            $anomalies[] = array(
                'type'    => 'new_country',
                'message' => "Login from new country: $country (known: " . implode(', ', $known_countries) . ")",
                'severity'=> 'warning',
            );
        }
        // Update known countries
        if ($country && ! in_array($country, $known_countries)) {
            $known_countries[] = $country;
            update_user_meta($user->ID, '_swps_known_countries', array_slice($known_countries, -10));
        }

        // 2. Odd hour (outside normal login hours)
        $settings_away = get_option('swps_settings', array());
        if ( ! empty($settings_away['anomaly_hours_check']) ) {
            $hour = intval(date('G'));
            if ( $hour >= 1 && $hour <= 5 ) {
                $anomalies[] = array(
                    'type'    => 'odd_hour',
                    'message' => "Login at unusual hour: " . date('H:i') . " (1am–5am)",
                    'severity'=> 'info',
                );
            }
        }

        // 3. Multiple countries in 24h (impossible travel)
        $recent_ips = get_user_meta($user->ID, '_swps_recent_login_ips', true) ?: array();
        $recent_countries = array();
        foreach ($recent_ips as $entry) {
            if (time() - $entry['time'] < DAY_IN_SECONDS && !empty($entry['country'])) {
                $recent_countries[] = $entry['country'];
            }
        }
        $unique_recent = array_unique($recent_countries);
        if (count($unique_recent) >= 3 && $country) {
            $anomalies[] = array(
                'type'    => 'impossible_travel',
                'message' => "Login from " . count($unique_recent) . " different countries in 24h: " . implode(', ', $unique_recent),
                'severity'=> 'critical',
            );
        }

        // Update recent IPs
        $recent_ips[] = array('ip'=>$ip,'country'=>$country,'time'=>time());
        $recent_ips = array_slice($recent_ips, -20); // Keep last 20
        update_user_meta($user->ID, '_swps_recent_login_ips', $recent_ips);

        // 4. New IP never seen before for admin
        if (user_can($user->ID, 'manage_options')) {
            $known_ips = get_user_meta($user->ID, '_swps_known_ips', true) ?: array();
            if (!empty($known_ips) && !in_array($ip, $known_ips)) {
                $anomalies[] = array(
                    'type'    => 'new_ip_admin',
                    'message' => "Admin login from NEW IP: $ip",
                    'severity'=> 'warning',
                );
            }
            if (!in_array($ip, $known_ips)) {
                $known_ips[] = $ip;
                update_user_meta($user->ID, '_swps_known_ips', array_slice($known_ips, -20));
            }
        }

        // 5. Password just changed = alert
        $pass_changed = get_user_meta($user->ID, '_swps_pass_changed', true);
        if ($pass_changed && (time() - intval($pass_changed)) < HOUR_IN_SECONDS) {
            $anomalies[] = array(
                'type'    => 'recent_pass_change',
                'message' => "Login shortly after password was changed (within 1 hour)",
                'severity'=> 'warning',
            );
        }

        // Process anomalies
        if (!empty($anomalies)) {
            $critical = array_filter($anomalies, fn($a) => $a['severity'] === 'critical');
            $severity = !empty($critical) ? 'critical' : 'warning';

            $msg = "Login anomalies for {$user->user_login} (IP: $ip):\n";
            foreach ($anomalies as $a) $msg .= "- [{$a['severity']}] {$a['message']}\n";

            SWPS_Activity_Log::add('login_anomaly', $severity, $msg);

            if ($severity === 'critical' || !empty($settings['anomaly_alert_all'])) {
                SWPS_Notifications::send(
                    'login_anomaly',
                    'WP Secure Pro: Login Anomaly Detected',
                    $msg,
                    $severity
                );
            }

            // Store anomaly for the admin UI
            $history = get_option('swps_anomaly_history', array());
            array_unshift($history, array(
                'user_id'    => $user->ID,
                'user_login' => $user->user_login,
                'ip'         => $ip,
                'country'    => $country,
                'anomalies'  => $anomalies,
                'time'       => time(),
            ));
            update_option('swps_anomaly_history', array_slice($history, 0, 100));
        }
    }

    private static function get_country($ip) {
        if (class_exists('SWPS_GeoIP')) {
            return SWPS_GeoIP::get_country($ip);
        }
        return null;
    }

    public static function get_history($limit = 50) {
        $history = get_option('swps_anomaly_history', array());
        return array_slice($history, 0, $limit);
    }
}
