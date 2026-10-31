<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Security_Headers {

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['security_headers_enabled'] ) ) return;
        add_action( 'send_headers', array( __CLASS__, 'send' ), 1 );
    }

    public static function send() {
        $h = get_option( 'swps_headers', array() );

        if ( ! empty( $h['x_frame_options'] ) ) {
            header( 'X-Frame-Options: ' . sanitize_text_field( $h['x_frame_options'] ) );
        }
        if ( ! empty( $h['x_content_type'] ) ) {
            header( 'X-Content-Type-Options: nosniff' );
        }
        if ( ! empty( $h['x_xss_protection'] ) ) {
            header( 'X-XSS-Protection: 1; mode=block' );
        }
        if ( ! empty( $h['referrer_policy'] ) ) {
            header( 'Referrer-Policy: ' . sanitize_text_field( $h['referrer_policy'] ) );
        }
        if ( ! empty( $h['hsts'] ) && is_ssl() ) {
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
        }
        if ( ! empty( $h['permissions_policy'] ) ) {
            header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        }
        if ( ! empty( $h['csp'] ) && ! empty( $h['csp_value'] ) ) {
            header( 'Content-Security-Policy: ' . $h['csp_value'] );
        }
        // Remove server info
        if ( ! empty( $h['remove_server_header'] ) ) {
            header_remove( 'X-Powered-By' );
            header_remove( 'Server' );
        }
    }

    public static function get_defaults() {
        return array(
            'x_frame_options'    => 'SAMEORIGIN',
            'x_content_type'     => 1,
            'x_xss_protection'   => 1,
            'referrer_policy'    => 'strict-origin-when-cross-origin',
            'hsts'               => 1,
            'permissions_policy' => 1,
            'remove_server_header'=> 1,
            'csp'                => 0,
            'csp_value'          => "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:;",
        );
    }

    public static function test_headers( $url = null ) {
        $url  = $url ?: get_site_url();
        $resp = wp_remote_head( $url, array( 'timeout' => 10, 'sslverify' => false ) );
        if ( is_wp_error($resp) ) return array();

        $headers = wp_remote_retrieve_headers( $resp );
        $checks  = array(
            'X-Frame-Options'           => 'X-Frame-Options',
            'X-Content-Type-Options'    => 'X-Content-Type-Options',
            // X-XSS-Protection intentionally not checked — it is deprecated and
            // modern browsers ignore it (OWASP recommends not relying on it).
            'Referrer-Policy'           => 'Referrer-Policy',
            'Strict-Transport-Security' => 'HSTS',
            'Content-Security-Policy'   => 'CSP',
            'Permissions-Policy'        => 'Permissions-Policy',
        );
        $results = array();
        foreach ( $checks as $header => $label ) {
            $results[] = array(
                'header'  => $label,
                'present' => ! empty( $headers[ strtolower($header) ] ),
                'value'   => $headers[ strtolower($header) ] ?? '',
            );
        }
        return $results;
    }

    public static function get_score( $test_results ) {
        if ( empty($test_results) ) return 0;
        $present = count( array_filter( $test_results, fn($r) => $r['present'] ) );
        return round( ( $present / count($test_results) ) * 100 );
    }
}
