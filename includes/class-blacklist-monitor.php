<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Blacklist_Monitor {

    const CACHE_KEY = 'swps_blacklist_status';
    const CACHE_TTL = 6 * HOUR_IN_SECONDS;

    public static function init() {
        add_action( 'swps_daily_cron',             array( __CLASS__, 'auto_check' ) );
        add_action( 'wp_ajax_swps_check_blacklist', array( __CLASS__, 'ajax_check' ) );
    }

    public static function ajax_check() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $results = self::check( true );
        wp_send_json_success( $results );
    }

    public static function auto_check() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['blacklist_monitor_enabled'] ) ) return;
        $results = self::check();
        foreach ( $results as $service => $data ) {
            if ( ! empty( $data['listed'] ) ) {
                SWPS_Activity_Log::add( 'blacklist_found', 'critical', "Site blacklisted on: $service" );
                SWPS_Email_Alerts::send_alert(
                    'SecureWP Shield: Site is Blacklisted!',
                    "Your site has been flagged by $service as unsafe.\n\nCheck the Security Scanner > Blacklist Monitor section for details."
                );
            }
        }
    }

    public static function check( $force = false ) {
        if ( ! $force ) {
            $cached = get_transient( self::CACHE_KEY );
            if ( $cached !== false ) return $cached;
        }

        $url     = get_site_url();
        $domain  = parse_url( $url, PHP_URL_HOST );
        $results = array();

        // Google Safe Browsing API
        $results['google_safe_browsing'] = self::check_google_safe_browsing( $url );

        // URLVoid / DNSBL approach for common blocklists (no API needed)
        $results['google_transparency'] = self::check_google_transparency( $domain );
        $results['norton_safe_web']      = self::check_norton( $domain );
        $results['sucuri_blacklist']     = self::check_sucuri( $domain );
        $results['spam_database']        = self::check_spam_dnsbl( $domain );

        $results['checked_at'] = time();

        set_transient( self::CACHE_KEY, $results, self::CACHE_TTL );
        update_option( 'swps_blacklist_last_check', $results );
        return $results;
    }

    private static function check_google_safe_browsing( $url ) {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['gsb_api_key'] ?? '';

        if ( ! $api_key ) {
            return array( 'name' => 'Google Safe Browsing', 'listed' => null, 'note' => 'API key not configured', 'url' => 'https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com' );
        }

        $body     = json_encode( array(
            'client'     => array( 'clientId' => 'securewp-shield', 'clientVersion' => SWPS_VERSION ),
            'threatInfo' => array(
                'threatTypes'      => array('MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'),
                'platformTypes'    => array('ANY_PLATFORM'),
                'threatEntryTypes' => array('URL'),
                'threatEntries'    => array( array('url' => $url) ),
            ),
        ) );
        $response = wp_remote_post( "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$api_key}", array(
            'body'    => $body,
            'headers' => array('Content-Type' => 'application/json'),
            'timeout' => 10,
        ) );

        if ( is_wp_error($response) ) return array( 'name' => 'Google Safe Browsing', 'listed' => null, 'note' => $response->get_error_message() );

        $data   = json_decode( wp_remote_retrieve_body($response), true );
        $listed = ! empty( $data['matches'] );

        return array(
            'name'   => 'Google Safe Browsing',
            'listed' => $listed,
            'note'   => $listed ? 'Site flagged by Google Safe Browsing' : 'Not listed',
        );
    }

    private static function check_google_transparency( $domain ) {
        // Check Google Transparency Report via public endpoint
        $encoded  = base64_encode( "\n" . $domain );
        $response = wp_remote_get( "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={$domain}", array('timeout' => 5) );

        if ( is_wp_error($response) ) return array( 'name' => 'Google Transparency', 'listed' => null, 'note' => 'Check failed' );

        $body   = wp_remote_retrieve_body($response);
        // Response is JavaScript-like — check for unsafe status strings
        $listed = strpos($body, '"UNSAFE"') !== false || strpos($body, '"SUSPICIOUS"') !== false;

        return array(
            'name'   => 'Google Transparency Report',
            'listed' => $listed,
            'note'   => $listed ? 'Site flagged in Google Transparency Report' : 'Not listed',
        );
    }

    private static function check_norton( $domain ) {
        $response = wp_remote_get( "https://safeweb.norton.com/report/show?url={$domain}", array('timeout'=>5) );
        if ( is_wp_error($response) ) return array( 'name' => 'Norton Safe Web', 'listed' => null, 'note' => 'Check failed' );

        $body   = wp_remote_retrieve_body($response);
        $listed = strpos( $body, 'Caution' ) !== false || strpos( $body, 'Dangerous' ) !== false;

        return array(
            'name'   => 'Norton Safe Web',
            'listed' => $listed,
            'note'   => $listed ? 'Site flagged by Norton Safe Web' : 'Not listed',
        );
    }

    private static function check_sucuri( $domain ) {
        $response = wp_remote_get( "https://sitecheck.sucuri.net/api/v3/?scan={$domain}", array('timeout'=>8) );
        if ( is_wp_error($response) ) return array( 'name' => 'Sucuri SiteCheck', 'listed' => null, 'note' => 'Check failed' );

        $data   = json_decode( wp_remote_retrieve_body($response), true );
        $listed = ! empty( $data['blacklists'] ) || ! empty( $data['malware'] );

        return array(
            'name'   => 'Sucuri SiteCheck',
            'listed' => $listed,
            'note'   => $listed ? 'Site flagged by Sucuri' : 'Not listed',
        );
    }

    private static function check_spam_dnsbl( $domain ) {
        // Spamhaus DBL. Must validate the RETURN code, not just existence:
        // real listings answer 127.0.1.2–127.0.1.99. A 127.255.255.x answer
        // means the query went through a public/blocked resolver (common on
        // shared hosting) and is NOT a real listing — ignore it to avoid a
        // false "blacklisted" on every domain.
        $listed  = false;
        $records = @dns_get_record( $domain . '.dbl.spamhaus.org', DNS_A );
        if ( ! empty( $records ) ) {
            foreach ( $records as $r ) {
                $ip = $r['ip'] ?? '';
                if ( preg_match( '/^127\.0\.1\.(\d+)$/', $ip, $m ) && (int) $m[1] >= 2 && (int) $m[1] <= 99 ) {
                    $listed = true;
                    break;
                }
            }
        }
        return array(
            'name'   => 'Spamhaus DBL',
            'listed' => $listed,
            'note'   => $listed ? 'Domain listed in Spamhaus DBL (spam domain list)' : 'Not listed',
        );
    }

    public static function is_any_blacklisted( $results = null ) {
        if ( ! $results ) $results = get_option( 'swps_blacklist_last_check', array() );
        foreach ( $results as $key => $data ) {
            if ( is_array($data) && ! empty($data['listed']) ) return true;
        }
        return false;
    }
}
