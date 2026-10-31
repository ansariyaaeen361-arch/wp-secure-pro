<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Away_Mode {

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['away_mode_enabled'] ) ) return;

        add_action( 'init', array( __CLASS__, 'check_access' ), 5 );
    }

    public static function check_access() {
        // Fix: this used to match 'wp-admin'/'wp-login' as a substring
        // ANYWHERE in the URL, including /wp-admin/admin-ajax.php — which
        // blocked every AJAX-dependent feature on the whole site during
        // "away hours" (this plugin's own public AJAX actions among them:
        // Fake Login's submit handler, 2FA email OTP resend, etc.), not just
        // the actual admin area. Only lock the real admin entry points.
        $request = trim( parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH ), '/' );
        if ( strpos( $request, 'admin-ajax.php' ) !== false ) return;
        $is_admin_url = ( preg_match( '#(^|/)wp-admin(/|$)#', $request ) || preg_match( '#(^|/)wp-login\.php($|/)#', $request ) );
        if ( ! $is_admin_url ) return;

        // Already logged in admins are never locked out
        if ( is_user_logged_in() && current_user_can('manage_options') ) return;

        $settings     = get_option( 'swps_settings', array() );
        $tz           = $settings['away_timezone'] ?? get_option('timezone_string') ?: 'UTC';
        $start_hour   = intval( $settings['away_start'] ?? 22 ); // default: 10 PM
        $end_hour     = intval( $settings['away_end']   ?? 6  ); // default: 6 AM

        try {
            $now = new DateTime( 'now', new DateTimeZone( $tz ) );
        } catch ( Exception $e ) {
            $now = new DateTime( 'now', new DateTimeZone('UTC') );
        }
        $hour = intval( $now->format('G') );

        $is_away = self::hour_in_range( $hour, $start_hour, $end_hour );

        // Check if today is a blocked day
        $blocked_days = $settings['away_days'] ?? array();
        if ( ! empty($blocked_days) ) {
            $day_of_week = $now->format('l'); // e.g. Monday
            if ( in_array( $day_of_week, (array) $blocked_days ) ) $is_away = true;
        }

        if ( $is_away ) {
            $ip   = SWPS_Login_Protection::get_client_ip();
            $time = $now->format('Y-m-d H:i T');
            SWPS_Activity_Log::add( 'away_mode_block', 'info', "Away Mode: admin login attempt blocked from $ip at $time" );

            status_header(503);
            nocache_headers();
            wp_die(
                '<h1>Site Temporarily Unavailable</h1><p>The admin area is locked outside of business hours. Please try again later.</p>',
                'Admin Locked',
                array( 'response' => 503 )
            );
        }
    }

    /**
     * Handles wrapping ranges (e.g. 22:00 to 06:00 crosses midnight).
     */
    private static function hour_in_range( $hour, $start, $end ) {
        if ( $start === $end ) return false;
        if ( $start < $end ) {
            return $hour >= $start && $hour < $end;
        }
        // Crosses midnight
        return $hour >= $start || $hour < $end;
    }

    public static function get_current_status() {
        $settings   = get_option( 'swps_settings', array() );
        if ( empty( $settings['away_mode_enabled'] ) ) return array( 'enabled' => false, 'locked' => false );

        $tz         = $settings['away_timezone'] ?? get_option('timezone_string') ?: 'UTC';
        $start_hour = intval( $settings['away_start'] ?? 22 );
        $end_hour   = intval( $settings['away_end']   ?? 6  );

        try {
            $now = new DateTime( 'now', new DateTimeZone( $tz ) );
        } catch ( Exception $e ) {
            $now = new DateTime( 'now', new DateTimeZone('UTC') );
        }
        $hour   = intval( $now->format('G') );
        $locked = self::hour_in_range( $hour, $start_hour, $end_hour );

        return array(
            'enabled'    => true,
            'locked'     => $locked,
            'local_time' => $now->format('D, M j Y H:i T'),
            'start'      => sprintf('%02d:00', $start_hour),
            'end'        => sprintf('%02d:00', $end_hour),
        );
    }
}
