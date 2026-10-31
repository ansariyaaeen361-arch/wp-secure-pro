<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Threat_Feed {

    const ABUSEIPDB_API = 'https://api.abuseipdb.com/api/v2/check';
    const CACHE_PREFIX  = 'swps_threat_';
    const CACHE_TTL     = 6 * HOUR_IN_SECONDS;
    const AUTO_BLOCK_SCORE = 90; // Block if AbuseIPDB confidence >= 90%

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['threat_feed_enabled']) || empty($settings['abuseipdb_key']) ) return;

        add_action( 'init',               array( __CLASS__, 'check_current_ip' ), 3 );
        add_action( 'swps_daily_cron',    array( __CLASS__, 'refresh_bulk_feed' ) );
        add_action( 'wp_ajax_swps_threat_check_ip', array( __CLASS__, 'ajax_check_ip' ) );
        add_action( 'wp_ajax_swps_report_ip',       array( __CLASS__, 'ajax_report_ip' ) );
    }

    /* ── Real-time check ─────────────────────────────────────────────────── */

    public static function check_current_ip() {
        if ( is_admin() ) return;
        if ( is_user_logged_in() && current_user_can('manage_options') ) return;

        $ip     = SWPS_Login_Protection::get_client_ip();
        // Skip private / reserved IPs.
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) return;

        $result = self::check_ip( $ip );
        if ( ! $result ) return;

        $score = $result['abuseConfidenceScore'] ?? 0;
        if ( $score >= self::AUTO_BLOCK_SCORE ) {
            $is_blocked = SWPS_IP_Blocker::is_blocked($ip);
            if ( ! $is_blocked ) {
                SWPS_IP_Blocker::block_ip( $ip, "AbuseIPDB score: $score%", 1440 ); // 24 hour block
                SWPS_Activity_Log::add( 'threat_feed_block', 'critical',
                    "IP $ip auto-blocked — AbuseIPDB confidence score: $score%" );
            }
        }
    }

    /* ── Check single IP ─────────────────────────────────────────────────── */

    public static function check_ip( $ip, $force = false ) {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['abuseipdb_key'] ?? '';
        if ( ! $api_key ) return null;

        // Skip private IPs
        if ( ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ) return null;

        $cache_key = self::CACHE_PREFIX . md5($ip);
        if ( ! $force ) {
            $cached = get_transient($cache_key);
            if ( $cached !== false ) return $cached;
        }

        $response = wp_remote_get( self::ABUSEIPDB_API . '?ipAddress=' . urlencode($ip) . '&maxAgeInDays=90&verbose', array(
            'headers' => array(
                'Key'    => $api_key,
                'Accept' => 'application/json',
            ),
            'timeout' => 5,
        ) );

        if ( is_wp_error($response) ) return null;
        $body = json_decode( wp_remote_retrieve_body($response), true );
        $data = $body['data'] ?? null;

        if ( $data ) set_transient($cache_key, $data, self::CACHE_TTL);
        return $data;
    }

    /* ── Report IP to AbuseIPDB ──────────────────────────────────────────── */

    public static function report_ip( $ip, $categories = array(18,21), $comment = '' ) {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['abuseipdb_key'] ?? '';
        if ( ! $api_key ) return false;

        $response = wp_remote_post( 'https://api.abuseipdb.com/api/v2/report', array(
            'headers' => array(
                'Key'    => $api_key,
                'Accept' => 'application/json',
            ),
            'body' => array(
                'ip'         => $ip,
                'categories' => implode(',', $categories), // 18=BruteForce, 21=WebAppAttack
                'comment'    => $comment ?: 'Detected by SecureWP Shield WordPress Security Plugin',
            ),
            'timeout' => 5,
        ) );

        if ( is_wp_error($response) ) return false;
        $body = json_decode( wp_remote_retrieve_body($response), true );
        return ! empty($body['data']['abuseConfidenceScore']);
    }

    /* ── AJAX handlers ───────────────────────────────────────────────────── */

    public static function ajax_check_ip() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $ip   = sanitize_text_field( $_POST['ip'] ?? '' );
        $data = self::check_ip($ip, true);

        if ( ! $data ) wp_send_json_error('Check failed or API key not set.');
        wp_send_json_success( $data );
    }

    public static function ajax_report_ip() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $ip      = sanitize_text_field( $_POST['ip'] ?? '' );
        $comment = sanitize_text_field( $_POST['comment'] ?? '' );
        $result  = self::report_ip($ip, array(18,21), $comment);

        if ($result) {
            SWPS_Activity_Log::add( 'ip_reported', 'info', "IP $ip reported to AbuseIPDB" );
            wp_send_json_success('IP reported to AbuseIPDB.');
        } else {
            wp_send_json_error('Report failed.');
        }
    }

    /* ── Bulk blocklist from AbuseIPDB ───────────────────────────────────── */

    public static function refresh_bulk_feed() {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['abuseipdb_key'] ?? '';
        if ( ! $api_key || empty($settings['threat_feed_bulk']) ) return;

        $response = wp_remote_get( 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=1000', array(
            'headers' => array( 'Key' => $api_key, 'Accept' => 'application/json' ),
            'timeout' => 15,
        ) );

        if ( is_wp_error($response) ) return;
        $body = json_decode( wp_remote_retrieve_body($response), true );
        $ips  = $body['data'] ?? array();

        $blocked = 0;
        foreach ( $ips as $entry ) {
            $ip = $entry['ipAddress'] ?? '';
            if ( $ip && ! SWPS_IP_Blocker::is_blocked($ip) ) {
                SWPS_IP_Blocker::block_ip( $ip, 'AbuseIPDB bulk feed (score ≥90%)', 1440 );
                $blocked++;
            }
        }

        update_option( 'swps_threat_feed_last_refresh', array( 'time' => time(), 'blocked' => $blocked ) );
        SWPS_Activity_Log::add( 'threat_feed_refresh', 'info', "AbuseIPDB bulk feed refreshed — $blocked new IPs blocked" );
    }

    public static function get_reputation_badge( $score ) {
        if ( $score === null ) return array('label' => 'Unknown', 'class' => 'warning');
        if ( $score >= 80 ) return array('label' => "Malicious ($score%)", 'class' => 'critical');
        if ( $score >= 40 ) return array('label' => "Suspicious ($score%)", 'class' => 'warning');
        return array('label' => "Clean ($score%)", 'class' => 'ok');
    }
}
