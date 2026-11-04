<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Login_Protection {

    public static function init() {
        add_action( 'wp_login_failed',  array( __CLASS__, 'on_login_failed' ) );
        add_action( 'wp_login',         array( __CLASS__, 'on_login_success' ), 10, 2 );
        add_filter( 'authenticate',     array( __CLASS__, 'check_ip_blocked' ), 1, 3 );
        add_action( 'login_init',       array( __CLASS__, 'check_login_attempts' ) );
        // Clean old attempts every hour
        add_action( 'swps_hourly_check', array( __CLASS__, 'clean_old_attempts' ) );
    }

    public static function get_client_ip() {
        $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
        if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) return '0.0.0.0';

        // Forwarded headers are supplied by the client unless the immediate
        // peer is a proxy we explicitly trust. Never let an attacker choose a
        // new IP per request and bypass WAF/login rate limits.
        $settings = get_option( 'swps_settings', array() );
        $trusted  = preg_split( '/[\s,]+/', (string) ( $settings['trusted_proxy_ips'] ?? '' ), -1, PREG_SPLIT_NO_EMPTY );
        if ( ! in_array( $remote, $trusted, true ) ) return $remote;

        foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $key ) {
            if ( empty( $_SERVER[ $key ] ) ) continue;
            $ip = trim( explode( ',', (string) $_SERVER[ $key ] )[0] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
        }
        return $remote;
    }

    public static function check_ip_blocked( $user, $username, $password ) {
        $ip = self::get_client_ip();
        if ( SWPS_IP_Blocker::is_whitelisted( $ip ) ) return $user;
        if ( SWPS_IP_Blocker::is_blocked( $ip ) ) {
            SWPS_Activity_Log::add( 'blocked_ip_login', 'warning', "Blocked IP tried to login: $ip (user: $username)" );
            return new WP_Error( 'ip_blocked', '<strong>Error:</strong> Your IP address has been blocked due to too many failed login attempts. Please try again later.' );
        }
        return $user;
    }

    public static function check_login_attempts() {
        $ip       = self::get_client_ip();
        if ( SWPS_IP_Blocker::is_whitelisted( $ip ) ) return;
        $settings = get_option( 'swps_settings', array() );
        $max      = intval( $settings['max_login_attempts'] ?? 5 );
        $duration = intval( $settings['lockout_duration'] ?? 30 );

        if ( SWPS_IP_Blocker::is_blocked( $ip ) ) return;

        $count = self::get_attempts_count( $ip, $duration );

        if ( $count >= $max ) {
            $reason = "Too many failed logins ($count attempts in {$duration} min)";
            SWPS_IP_Blocker::block_ip( $ip, $reason, $duration );
            SWPS_Activity_Log::add( 'auto_ip_blocked', 'warning', "IP auto-blocked: $ip - $reason" );

            $settings = get_option( 'swps_settings', array() );
            if ( ! empty( $settings['alert_login_fail'] ) ) {
                SWPS_Email_Alerts::send_alert(
                    'Security Alert: IP Blocked - ' . get_bloginfo('name'),
                    "An IP address has been automatically blocked on your site.\n\n" .
                    "IP Address : $ip\n" .
                    "Reason     : $reason\n" .
                    "Blocked for: {$duration} minutes\n" .
                    "Site       : " . get_site_url() . "\n" .
                    "Time       : " . current_time('mysql')
                );
            }
        }
    }

    public static function on_login_failed( $username ) {
        global $wpdb;
        $ip = self::get_client_ip();

        $wpdb->insert(
            $wpdb->prefix . SWPS_TABLE_LOGINS,
            array(
                'ip_address'   => $ip,
                'username'     => $username,
                'attempted_at' => current_time('mysql'),
            ),
            array('%s', '%s', '%s')
        );

        $settings = get_option( 'swps_settings', array() );
        $max      = intval( $settings['max_login_attempts'] ?? 5 );
        $count    = self::get_attempts_count( $ip, intval( $settings['lockout_duration'] ?? 30 ) );

        SWPS_Activity_Log::add(
            'login_failed',
            $count >= ( $max - 1 ) ? 'warning' : 'info',
            "Failed login for '$username' from $ip (attempt $count of $max)"
        );
    }

    public static function on_login_success( $user_login, $user ) {
        SWPS_Activity_Log::add( 'login_success', 'info', "Successful login: $user_login from " . self::get_client_ip() );
        // Clear failed attempts for this IP on success
        global $wpdb;
        $ip = self::get_client_ip();
        $wpdb->delete( $wpdb->prefix . SWPS_TABLE_LOGINS, array('ip_address' => $ip), array('%s') );
    }

    public static function get_attempts_count( $ip, $minutes = 30 ) {
        global $wpdb;
        return (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}swps_login_attempts
             WHERE ip_address = %s AND attempted_at > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
            $ip, $minutes
        ) );
    }

    public static function clean_old_attempts() {
        global $wpdb;
        $wpdb->query( "DELETE FROM {$wpdb->prefix}swps_login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)" );
        // Unblock expired IPs
        $wpdb->query( "DELETE FROM {$wpdb->prefix}swps_blocked_ips WHERE expires_at IS NOT NULL AND expires_at < NOW()" );
    }

    public static function get_recent_failed_logins( $limit = 20 ) {
        global $wpdb;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT ip_address, username, COUNT(*) as attempts, MAX(attempted_at) as last_attempt
             FROM {$wpdb->prefix}swps_login_attempts
             GROUP BY ip_address, username
             ORDER BY last_attempt DESC LIMIT %d",
            $limit
        ) );
    }
}
