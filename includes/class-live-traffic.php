<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Live_Traffic {

    const TRANSIENT_KEY = 'swps_live_traffic';
    const MAX_ENTRIES   = 200;

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['live_traffic_enabled'] ) ) return;

        add_action( 'init', array( __CLASS__, 'record_visit' ), 99 );
        add_action( 'wp_ajax_swps_live_traffic_data',        array( __CLASS__, 'ajax_get_data' ) );
        add_action( 'wp_ajax_swps_live_traffic_clear',       array( __CLASS__, 'ajax_clear' ) );
    }

    public static function record_visit() {
        // Skip admin, cron, AJAX, asset requests
        if ( is_admin() ) return;
        if ( defined('DOING_CRON') && DOING_CRON ) return;

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        // Skip common asset extensions
        if ( preg_match('/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)(\?|$)/i', $uri ) ) return;

        $ip        = SWPS_Login_Protection::get_client_ip();
        $ua        = substr( sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown' ), 0, 200 );
        $referer   = substr( sanitize_text_field( $_SERVER['HTTP_REFERER'] ?? '' ), 0, 300 );
        $method    = sanitize_text_field( $_SERVER['REQUEST_METHOD'] ?? 'GET' );
        $is_bot    = self::detect_bot( $ua );
        $is_logged = is_user_logged_in();
        $country   = get_transient( SWPS_GeoIP::CACHE_KEY . md5($ip) ) ?: '';

        $entry = array(
            'time'      => time(),
            'ip'        => $ip,
            'uri'       => substr( $uri, 0, 200 ),
            'method'    => $method,
            'ua'        => $ua,
            'referer'   => $referer,
            'bot'       => $is_bot,
            'logged_in' => $is_logged,
            'country'   => $country,
            'status'    => http_response_code() ?: 200,
        );

        $log = get_transient( self::TRANSIENT_KEY ) ?: array();
        array_unshift( $log, $entry );
        if ( count($log) > self::MAX_ENTRIES ) $log = array_slice( $log, 0, self::MAX_ENTRIES );
        set_transient( self::TRANSIENT_KEY, $log, HOUR_IN_SECONDS );
    }

    private static function detect_bot( $ua ) {
        if ( ! $ua ) return true;
        $bot_patterns = array(
            'bot','crawl','spider','slurp','scan','scraper',
            'wget','curl','python-requests','java/','libwww',
            'ahrefsbot','mj12bot','semrushbot','dotbot',
            'rogerbot','blexbot','seznambot','yandexbot',
        );
        $ua_lower = strtolower( $ua );
        foreach ( $bot_patterns as $p ) {
            if ( strpos( $ua_lower, $p ) !== false ) return true;
        }
        return false;
    }

    public static function ajax_get_data() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $log = get_transient( self::TRANSIENT_KEY ) ?: array();

        $filter = sanitize_text_field( $_POST['filter'] ?? 'all' );
        if ( $filter === 'bots' )    $log = array_filter( $log, fn($e) => $e['bot'] );
        if ( $filter === 'humans' )  $log = array_filter( $log, fn($e) => ! $e['bot'] );
        if ( $filter === 'blocked' ) {
            $log = array_filter( $log, fn($e) => SWPS_IP_Blocker::is_blocked($e['ip']) );
        }

        $stats = self::get_stats( get_transient( self::TRANSIENT_KEY ) ?: array() );

        wp_send_json_success( array(
            'entries' => array_values( array_slice( $log, 0, 50 ) ),
            'stats'   => $stats,
        ) );
    }

    public static function ajax_clear() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        delete_transient( self::TRANSIENT_KEY );
        wp_send_json_success();
    }

    public static function get_stats( $log ) {
        if ( empty($log) ) return array( 'total'=>0,'bots'=>0,'humans'=>0,'unique_ips'=>0,'top_ips'=>array() );

        $bots   = count( array_filter( $log, fn($e) => $e['bot'] ) );
        $ips    = array_column( $log, 'ip' );
        $ip_counts = array_count_values( $ips );
        arsort( $ip_counts );

        return array(
            'total'      => count($log),
            'bots'       => $bots,
            'humans'     => count($log) - $bots,
            'unique_ips' => count( array_unique($ips) ),
            'top_ips'    => array_slice( $ip_counts, 0, 5, true ),
        );
    }
}
