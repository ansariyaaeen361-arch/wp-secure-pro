<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Vuln_Scanner {

    const API_BASE     = 'https://wpscan.com/api/v3';
    const CACHE_PREFIX = 'swps_vuln_';
    const CACHE_TTL    = 12 * HOUR_IN_SECONDS;

    public static function init() {
        add_action( 'wp_ajax_swps_run_vuln_scan',    array( __CLASS__, 'ajax_run_scan' ) );
        add_action( 'swps_daily_cron',               array( __CLASS__, 'maybe_auto_scan' ) );
    }

    public static function ajax_run_scan() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $results = self::run_scan( true );
        wp_send_json_success( $results );
    }

    public static function run_scan( $force = false ) {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['wpscan_api_key'] ?? '';

        $results = array(
            'scanned_at' => time(),
            'wordpress'  => self::check_wordpress( $api_key, $force ),
            'plugins'    => self::check_plugins( $api_key, $force ),
            'themes'     => self::check_themes( $api_key, $force ),
            'total_vulns'=> 0,
            'has_api'    => ! empty( $api_key ),
        );

        // Count total vulnerabilities
        $total = count( $results['wordpress']['vulnerabilities'] ?? array() );
        foreach ( $results['plugins'] as $p ) {
            $total += count( $p['vulnerabilities'] ?? array() );
        }
        foreach ( $results['themes'] as $t ) {
            $total += count( $t['vulnerabilities'] ?? array() );
        }
        $results['total_vulns'] = $total;

        update_option( 'swps_last_vuln_scan', $results );

        if ( $total > 0 ) {
            SWPS_Activity_Log::add( 'vuln_scan', 'critical', "Vulnerability scan found $total vulnerabilities" );
            SWPS_Email_Alerts::send_alert(
                'WP Secure Pro: Vulnerabilities Found',
                "The vulnerability scanner found $total vulnerabilities on your site.\n\nPlease log in to your WordPress dashboard and review the Security Scanner page immediately."
            );
        } else {
            SWPS_Activity_Log::add( 'vuln_scan', 'info', 'Vulnerability scan completed — no vulnerabilities found' );
        }

        return $results;
    }

    private static function check_wordpress( $api_key, $force ) {
        global $wp_version;
        $cache_key = self::CACHE_PREFIX . 'wp_' . md5( $wp_version );

        if ( ! $force ) {
            $cached = get_transient( $cache_key );
            if ( $cached !== false ) return $cached;
        }

        $data = array(
            'version'         => $wp_version,
            'vulnerabilities' => array(),
            'status'          => 'unknown',
        );

        if ( $api_key ) {
            $response = self::api_request( '/wordpresses/' . str_replace('.', '', $wp_version), $api_key );
            if ( ! is_wp_error($response) && isset($response[$wp_version]['vulnerabilities']) ) {
                $data['vulnerabilities'] = self::parse_vulns( $response[$wp_version]['vulnerabilities'] );
            }
        } else {
            // No API key — check against known EOL versions
            $data['status'] = version_compare( $wp_version, '6.0', '<' ) ? 'outdated' : 'ok';
        }

        $data['status'] = empty($data['vulnerabilities']) ? 'ok' : 'vulnerable';
        set_transient( $cache_key, $data, self::CACHE_TTL );
        return $data;
    }

    private static function check_plugins( $api_key, $force ) {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        $results = array();

        foreach ( $plugins as $file => $plugin ) {
            $slug = dirname( $file );
            if ( $slug === '.' ) $slug = basename( $file, '.php' );

            $cache_key = self::CACHE_PREFIX . 'plugin_' . md5( $slug . $plugin['Version'] );
            $data      = null;

            if ( ! $force ) $data = get_transient( $cache_key );

            if ( $data === false || $data === null ) {
                $data = array(
                    'name'            => $plugin['Name'],
                    'slug'            => $slug,
                    'version'         => $plugin['Version'],
                    'vulnerabilities' => array(),
                    'status'          => 'ok',
                );

                if ( $api_key ) {
                    $response = self::api_request( '/plugins/' . $slug, $api_key );
                    if ( ! is_wp_error($response) && isset($response[$slug]['vulnerabilities']) ) {
                        $data['vulnerabilities'] = self::parse_vulns( $response[$slug]['vulnerabilities'] );
                        $data['status'] = 'vulnerable';
                    }
                }

                set_transient( $cache_key, $data, self::CACHE_TTL );
            }

            $results[] = $data;
        }

        return $results;
    }

    private static function check_themes( $api_key, $force ) {
        $themes  = wp_get_themes();
        $results = array();

        foreach ( $themes as $slug => $theme ) {
            $cache_key = self::CACHE_PREFIX . 'theme_' . md5( $slug . $theme->get('Version') );
            $data      = null;

            if ( ! $force ) $data = get_transient( $cache_key );

            if ( $data === false || $data === null ) {
                $data = array(
                    'name'            => $theme->get('Name'),
                    'slug'            => $slug,
                    'version'         => $theme->get('Version'),
                    'vulnerabilities' => array(),
                    'status'          => 'ok',
                );

                if ( $api_key ) {
                    $response = self::api_request( '/themes/' . $slug, $api_key );
                    if ( ! is_wp_error($response) && isset($response[$slug]['vulnerabilities']) ) {
                        $data['vulnerabilities'] = self::parse_vulns( $response[$slug]['vulnerabilities'] );
                        $data['status'] = 'vulnerable';
                    }
                }

                set_transient( $cache_key, $data, self::CACHE_TTL );
            }

            $results[] = $data;
        }

        return $results;
    }

    private static function api_request( $endpoint, $api_key ) {
        $response = wp_remote_get( self::API_BASE . $endpoint, array(
            'headers' => array( 'Authorization' => 'Token token=' . $api_key ),
            'timeout' => 10,
        ) );
        if ( is_wp_error($response) ) return $response;
        $code = wp_remote_retrieve_response_code($response);
        if ( $code === 429 ) return new WP_Error( 'rate_limited', 'WPScan API rate limit reached.' );
        if ( $code !== 200 ) return new WP_Error( 'api_error', "WPScan API returned HTTP $code" );
        return json_decode( wp_remote_retrieve_body($response), true );
    }

    private static function parse_vulns( $vulns ) {
        $out = array();
        foreach ( $vulns as $v ) {
            $out[] = array(
                'title'       => $v['title'] ?? 'Unknown',
                'cvss_score'  => $v['cvss']['score'] ?? null,
                'cve'         => $v['cve'] ?? '',
                'references'  => $v['references']['url'] ?? array(),
                'fixed_in'    => $v['fixed_in'] ?? null,
            );
        }
        return $out;
    }

    public static function maybe_auto_scan() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['vuln_auto_scan'] ) ) return;
        self::run_scan();
    }

    public static function get_api_status( $api_key ) {
        if ( ! $api_key ) return array( 'valid' => false, 'requests_remaining' => 0 );
        $response = wp_remote_get( self::API_BASE . '/status', array(
            'headers' => array( 'Authorization' => 'Token token=' . $api_key ),
            'timeout' => 5,
        ) );
        if ( is_wp_error($response) ) return array( 'valid' => false, 'error' => $response->get_error_message() );
        $body = json_decode( wp_remote_retrieve_body($response), true );
        return array(
            'valid'               => wp_remote_retrieve_response_code($response) === 200,
            'requests_remaining'  => $body['plan']['requests_remaining'] ?? 0,
            'plan'                => $body['plan']['name'] ?? 'Unknown',
        );
    }
}
