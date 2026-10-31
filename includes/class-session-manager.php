<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Session_Manager {

    public static function init() {
        add_action( 'wp_login',               array( __CLASS__, 'on_login' ), 10, 2 );
        add_action( 'wp_logout',              array( __CLASS__, 'on_logout' ) );
        add_action( 'swps_hourly_check',      array( __CLASS__, 'cleanup_old_sessions' ) );
        add_action( 'wp_ajax_swps_kill_session',    array( __CLASS__, 'ajax_kill_session' ) );
        add_action( 'wp_ajax_swps_kill_all_sessions', array( __CLASS__, 'ajax_kill_all_sessions' ) );
        add_action( 'wp_ajax_swps_kill_user_sessions', array( __CLASS__, 'ajax_kill_user_sessions' ) );
    }

    /* ── Track sessions ──────────────────────────────────────────────────── */

    public static function on_login( $user_login, $user ) {
        $sessions = get_option( 'swps_active_sessions', array() );
        $token    = wp_get_session_token();

        $sessions[ $token ] = array(
            'user_id'    => $user->ID,
            'user_login' => $user_login,
            'ip'         => SWPS_Login_Protection::get_client_ip(),
            'ua'         => substr( sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 ),
            'country'    => get_transient( SWPS_GeoIP::CACHE_KEY . md5( SWPS_Login_Protection::get_client_ip() ) ) ?: '',
            'login_time' => time(),
            'last_seen'  => time(),
        );

        // Concurrent session limit
        $settings = get_option( 'swps_settings', array() );
        $limit    = intval( $settings['max_sessions_per_user'] ?? 0 );
        if ( $limit > 0 ) {
            $user_sessions = array_filter( $sessions, fn($s) => $s['user_id'] === $user->ID );
            if ( count($user_sessions) > $limit ) {
                // Kill oldest sessions
                uasort( $user_sessions, fn($a,$b) => $a['login_time'] <=> $b['login_time'] );
                $to_kill = array_slice( array_keys($user_sessions), 0, count($user_sessions) - $limit );
                foreach ( $to_kill as $t ) {
                    self::destroy_session( $user->ID, $t );
                    unset($sessions[$t]);
                }
            }
        }

        update_option( 'swps_active_sessions', $sessions );

        // Anomaly detection
        if ( class_exists('SWPS_Anomaly_Detection') ) {
            SWPS_Anomaly_Detection::check_login( $user, SWPS_Login_Protection::get_client_ip() );
        }
    }

    public static function on_logout() {
        $token    = wp_get_session_token();
        $sessions = get_option( 'swps_active_sessions', array() );
        unset( $sessions[$token] );
        update_option( 'swps_active_sessions', $sessions );
    }

    /* ── Kill sessions ────────────────────────────────────────────────────── */

    public static function ajax_kill_session() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $token   = sanitize_text_field( $_POST['token'] ?? '' );
        $user_id = intval( $_POST['user_id'] ?? 0 );

        self::destroy_session( $user_id, $token );
        $sessions = get_option( 'swps_active_sessions', array() );
        unset( $sessions[$token] );
        update_option( 'swps_active_sessions', $sessions );

        SWPS_Activity_Log::add( 'session_killed', 'warning', "Admin force-killed session token for user #$user_id" );
        wp_send_json_success('Session terminated.');
    }

    public static function ajax_kill_all_sessions() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $sessions = get_option( 'swps_active_sessions', array() );
        $my_token = wp_get_session_token();

        foreach ( $sessions as $token => $data ) {
            if ( $token === $my_token ) continue; // Don't kill own session
            self::destroy_session( $data['user_id'], $token );
        }

        // Keep only current admin session
        $mine = $sessions[$my_token] ?? null;
        update_option( 'swps_active_sessions', $mine ? array($my_token => $mine) : array() );

        SWPS_Activity_Log::add( 'all_sessions_killed', 'critical', 'Admin force-terminated all active sessions' );
        wp_send_json_success('All sessions terminated.');
    }

    public static function ajax_kill_user_sessions() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $user_id  = intval( $_POST['user_id'] ?? 0 );
        $sessions = get_option( 'swps_active_sessions', array() );

        foreach ( $sessions as $token => $data ) {
            if ( $data['user_id'] === $user_id ) {
                self::destroy_session( $user_id, $token );
                unset($sessions[$token]);
            }
        }

        update_option( 'swps_active_sessions', $sessions );
        SWPS_Activity_Log::add( 'user_sessions_killed', 'warning', "All sessions terminated for user #$user_id" );
        wp_send_json_success('User sessions terminated.');
    }

    private static function destroy_session( $user_id, $token ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        $manager->destroy( $token );
    }

    /* ── Cleanup ─────────────────────────────────────────────────────────── */

    public static function cleanup_old_sessions() {
        $sessions = get_option( 'swps_active_sessions', array() );
        $cutoff   = time() - ( 7 * DAY_IN_SECONDS );
        foreach ( $sessions as $token => $data ) {
            if ( $data['last_seen'] < $cutoff ) unset($sessions[$token]);
        }
        update_option( 'swps_active_sessions', $sessions );
    }

    /* ── Getters ─────────────────────────────────────────────────────────── */

    public static function get_all_sessions() {
        return get_option( 'swps_active_sessions', array() );
    }

    public static function get_sessions_for_user( $user_id ) {
        $all = self::get_all_sessions();
        return array_filter( $all, fn($s) => $s['user_id'] === $user_id );
    }

    public static function get_stats() {
        $sessions = self::get_all_sessions();
        $admins   = array_filter( $sessions, fn($s) => user_can($s['user_id'], 'manage_options') );
        $unique   = array_unique( array_column($sessions, 'user_id') );
        return array(
            'total'        => count($sessions),
            'admin_count'  => count($admins),
            'unique_users' => count($unique),
        );
    }
}
