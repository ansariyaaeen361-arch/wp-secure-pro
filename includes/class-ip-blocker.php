<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_IP_Blocker {

    public static function init() {
        // Block IPs on every request (before WordPress loads fully)
        add_action( 'init', array( __CLASS__, 'check_current_ip' ), 1 );
    }

    public static function check_current_ip() {
        if ( is_admin() ) return; // Don't block admin panel access here
        $ip = SWPS_Login_Protection::get_client_ip();
        if ( self::is_blocked( $ip ) ) {
            status_header( 403 );
            die( '<h1>403 Forbidden</h1><p>Your IP address has been blocked. Contact the site administrator.</p>' );
        }
    }

    public static function get_ip() {
        return SWPS_Login_Protection::get_client_ip();
    }

    public static function is_whitelisted( $ip ) {
        $settings = get_option( 'swps_settings', array() );
        $raw      = $settings['waf_whitelist_ips'] ?? '';
        $list     = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) );
        return in_array( $ip, $list, true );
    }

    public static function is_blocked( $ip ) {
        global $wpdb;
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}swps_blocked_ips
             WHERE ip_address = %s AND (expires_at IS NULL OR expires_at > NOW())",
            $ip
        ) );
        return ! empty( $row );
    }

    public static function block_ip( $ip, $reason = '', $duration_minutes = null ) {
        global $wpdb;
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;

        $expires = null;
        if ( $duration_minutes ) {
            $expires = date( 'Y-m-d H:i:s', time() + ( $duration_minutes * 60 ) );
        }

        $wpdb->replace(
            $wpdb->prefix . SWPS_TABLE_IPS,
            array(
                'ip_address' => $ip,
                'reason'     => $reason,
                'blocked_at' => current_time('mysql'),
                'expires_at' => $expires,
            ),
            array('%s','%s','%s', $expires ? '%s' : null )
        );
        do_action( 'swps_ip_blocked', $ip, $reason );
        return true;
    }

    public static function unblock_ip( $ip ) {
        global $wpdb;
        $wpdb->delete( $wpdb->prefix . SWPS_TABLE_IPS, array('ip_address' => $ip), array('%s') );
        do_action( 'swps_ip_unblocked', $ip );
    }

    public static function get_blocked_ips( $limit = 100 ) {
        global $wpdb;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}swps_blocked_ips ORDER BY blocked_at DESC LIMIT %d",
            $limit
        ) );
    }

    public static function get_count() {
        global $wpdb;
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}swps_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()" );
    }
}
