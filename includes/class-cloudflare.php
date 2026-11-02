<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Cloudflare {

    const API_BASE = 'https://api.cloudflare.com/client/v4';

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['cloudflare_enabled']) ) return;

        // Sync blocks to CF when an IP is blocked
        add_action( 'swps_ip_blocked',   array( __CLASS__, 'on_ip_blocked' ), 10, 2 );
        add_action( 'swps_ip_unblocked', array( __CLASS__, 'on_ip_unblocked' ) );
        add_action( 'wp_ajax_swps_cf_sync',       array( __CLASS__, 'ajax_sync_all' ) );
        add_action( 'wp_ajax_swps_cf_test',       array( __CLASS__, 'ajax_test' ) );
        add_action( 'wp_ajax_swps_cf_purge_cache',array( __CLASS__, 'ajax_purge_cache' ) );
    }

    /* ── IP Block Sync ───────────────────────────────────────────────────── */

    public static function on_ip_blocked( $ip, $reason ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['cf_auto_sync']) ) return;
        self::block_ip_in_cf($ip, $reason);
    }

    public static function on_ip_unblocked( $ip ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['cf_auto_sync']) ) return;
        self::unblock_ip_in_cf($ip);
    }

    public static function block_ip_in_cf( $ip, $notes = '' ) {
        $settings = get_option( 'swps_settings', array() );
        $zone_id  = $settings['cf_zone_id'] ?? '';
        $api_key  = $settings['cf_api_key'] ?? '';
        $email    = $settings['cf_email']   ?? '';

        if ( ! $zone_id || ! $api_key ) return false;

        // Check if already exists
        $existing = self::get_cf_rule_for_ip($ip);
        if ( $existing ) return true;

        $response = self::api_request( "POST", "/zones/{$zone_id}/firewall/access_rules/rules", array(
            'mode'          => 'block',
            'configuration' => array( 'target' => 'ip', 'value' => $ip ),
            'notes'         => 'WP Secure Pro: ' . ($notes ?: 'Auto-blocked'),
        ) );

        if ( $response && ! empty($response['success']) ) {
            // Store CF rule ID for later removal
            $rule_map = get_option('swps_cf_rule_map', array());
            $rule_map[$ip] = $response['result']['id'] ?? '';
            update_option('swps_cf_rule_map', $rule_map);
            return true;
        }
        return false;
    }

    public static function unblock_ip_in_cf( $ip ) {
        $settings = get_option( 'swps_settings', array() );
        $zone_id  = $settings['cf_zone_id'] ?? '';

        $rule_map = get_option('swps_cf_rule_map', array());
        $rule_id  = $rule_map[$ip] ?? self::get_cf_rule_for_ip($ip);

        if ( ! $rule_id ) return false;

        $response = self::api_request( "DELETE", "/zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}" );

        if ( $response && ! empty($response['success']) ) {
            unset($rule_map[$ip]);
            update_option('swps_cf_rule_map', $rule_map);
            return true;
        }
        return false;
    }

    private static function get_cf_rule_for_ip( $ip ) {
        $settings = get_option( 'swps_settings', array() );
        $zone_id  = $settings['cf_zone_id'] ?? '';

        $response = self::api_request( "GET", "/zones/{$zone_id}/firewall/access_rules/rules?configuration.value={$ip}&configuration.target=ip" );
        if ( $response && ! empty($response['result'][0]['id']) ) {
            return $response['result'][0]['id'];
        }
        return null;
    }

    /* ── Bulk sync ───────────────────────────────────────────────────────── */

    public static function ajax_sync_all() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        global $wpdb;
        $table   = $wpdb->prefix . SWPS_TABLE_IPS;
        $blocked = $wpdb->get_col("SELECT ip_address FROM $table WHERE expires_at IS NULL OR expires_at > NOW()");

        $synced = 0;
        foreach ($blocked as $ip) {
            if ( self::block_ip_in_cf($ip, 'Synced from WP Secure Pro') ) $synced++;
        }

        wp_send_json_success("Synced $synced IPs to Cloudflare.");
    }

    /* ── Cache purge ─────────────────────────────────────────────────────── */

    public static function purge_cache( $urls = array() ) {
        $settings = get_option( 'swps_settings', array() );
        $zone_id  = $settings['cf_zone_id'] ?? '';

        $body = empty($urls) ? array('purge_everything' => true) : array('files' => $urls);
        $response = self::api_request("POST", "/zones/{$zone_id}/purge_cache", $body);
        return $response && ! empty($response['success']);
    }

    public static function ajax_purge_cache() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $result = self::purge_cache();
        $result ? wp_send_json_success('Cloudflare cache purged.') : wp_send_json_error('Purge failed.');
    }

    /* ── Connection test ─────────────────────────────────────────────────── */

    public static function test_connection() {
        $response = self::api_request("GET", "/user/tokens/verify");
        return $response && ! empty($response['success']);
    }

    public static function ajax_test() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $ok = self::test_connection();
        $ok ? wp_send_json_success('Cloudflare connection successful.') : wp_send_json_error('Connection failed — check API key.');
    }

    /* ── API helper ──────────────────────────────────────────────────────── */

    private static function api_request( $method, $endpoint, $body = null ) {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['cf_api_key'] ?? '';
        $email    = $settings['cf_email']   ?? '';

        $args = array(
            'method'  => $method,
            'headers' => array(
                'X-Auth-Email' => $email,
                'X-Auth-Key'   => $api_key,
                'Content-Type' => 'application/json',
            ),
            'timeout' => 10,
        );

        if ( $body !== null ) $args['body'] = json_encode($body);

        $response = wp_remote_request( self::API_BASE . $endpoint, $args );
        if ( is_wp_error($response) ) return null;
        return json_decode( wp_remote_retrieve_body($response), true );
    }

    public static function get_zone_info() {
        $settings = get_option( 'swps_settings', array() );
        $zone_id  = $settings['cf_zone_id'] ?? '';
        if ( ! $zone_id ) return null;

        $response = self::api_request("GET", "/zones/{$zone_id}");
        return $response['result'] ?? null;
    }
}
