<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Webhooks {

    public static function init() {
        add_action( 'wp_ajax_swps_test_webhook', array( __CLASS__, 'ajax_test' ) );
    }

    /**
     * Send event payload to all configured webhook URLs.
     *
     * @param string $event   Event slug e.g. 'login_failed', 'file_change', 'new_admin'
     * @param array  $data    Event-specific data
     */
    public static function send( $event, $data = array() ) {
        $settings = get_option( 'swps_settings', array() );
        $urls_raw = $settings['webhook_urls'] ?? '';
        $urls     = array_filter( array_map('trim', explode("\n", $urls_raw)) );

        if ( empty($urls) ) return;

        $events_filter = array_filter( array_map('trim', explode(',', $settings['webhook_events'] ?? '')) );
        if ( ! empty($events_filter) && ! in_array($event, $events_filter) ) return;

        $payload = array(
            'event'      => $event,
            'site'       => get_site_url(),
            'site_name'  => get_bloginfo('name'),
            'timestamp'  => time(),
            'datetime'   => date_i18n('Y-m-d H:i:s'),
            'data'       => $data,
            'plugin'     => 'SecureWP Shield v' . SWPS_VERSION,
        );

        $secret = $settings['webhook_secret'] ?? '';
        $body   = json_encode($payload);
        $sig    = $secret ? hash_hmac('sha256', $body, $secret) : '';

        foreach ( $urls as $url ) {
            if ( ! filter_var($url, FILTER_VALIDATE_URL) ) continue;

            $headers = array( 'Content-Type' => 'application/json' );
            if ( $sig ) $headers['X-SWPS-Signature'] = 'sha256=' . $sig;

            wp_remote_post( $url, array(
                'body'     => $body,
                'headers'  => $headers,
                'timeout'  => 5,
                'blocking' => false, // Non-blocking — fire and forget
            ) );
        }
    }

    public static function ajax_test() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        self::send('test', array(
            'message' => 'This is a test webhook from SecureWP Shield.',
            'admin'   => wp_get_current_user()->user_login,
        ) );

        wp_send_json_success('Test webhook sent to all configured URLs.');
    }

    /**
     * Get list of available events for the settings UI.
     */
    public static function get_available_events() {
        return array(
            'login_failed'    => 'Login Failed',
            'login_blocked'   => 'IP Auto-blocked',
            'new_admin'       => 'New Admin User Created',
            'rogue_admin'     => 'Rogue Admin Detected',
            'file_change'     => 'File Change Detected',
            'malware_found'   => 'Malware Scan Result',
            'waf_block'       => 'WAF Attack Blocked',
            'geoip_block'     => 'Country Blocked',
            'ssl_expiring'    => 'SSL Certificate Expiring',
            'ssl_expired'     => 'SSL Certificate Expired',
            'blacklist_found' => 'Site Blacklisted',
            'vuln_found'      => 'Vulnerability Found',
            'db_user_added'   => 'Unknown DB User',
            'away_blocked'    => 'Away Mode Block',
            'test'            => 'Test Event',
        );
    }
}
